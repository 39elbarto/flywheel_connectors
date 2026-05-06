//! QQ API configuration and response types.

use serde::{Deserialize, Serialize};

pub const DEFAULT_BASE_URL: &str = "https://api.sgroup.qq.com";
pub const DEFAULT_TOKEN_BASE_URL: &str = "https://bots.qq.com";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

pub const OP_SEND_CHANNEL: &str = "qq.messages.send_channel";
pub const OP_SEND_GROUP: &str = "qq.messages.send_group";
pub const OP_SEND_C2C: &str = "qq.messages.send_c2c";
pub const OP_GET_GATEWAY: &str = "qq.gateway.get";
pub const OP_GATEWAY_PROJECT_EVENT: &str = "qq.gateway.project_event";
pub const OP_HEALTH: &str = "qq.health";
pub const OP_EVENTS_NORMALIZE: &str = "qq.events.normalize";

pub const CAP_MESSAGES_WRITE: &str = "qq.messages.write";
pub const CAP_GATEWAY_READ: &str = "qq.gateway.read";
pub const CAP_HEALTH_READ: &str = "qq.health.read";
pub const CAP_EVENTS_READ: &str = "qq.events.read";

pub const EVENT_QQ_MESSAGE_AUTHORIZED: &str = "qq.message.authorized";
pub const EVENT_QQ_EVENT_DROPPED: &str = "qq.event.dropped";

fn trim_string(value: &mut String) {
    let trimmed = value.trim();
    if trimmed.len() != value.len() {
        *value = trimmed.to_string();
    }
}

fn trim_optional_string(value: &mut Option<String>) {
    if let Some(raw) = value {
        trim_string(raw);
        if raw.is_empty() {
            *value = None;
        }
    }
}

fn normalize_string_vec(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        trim_string(value);
    }
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
}

#[derive(Clone, Deserialize)]
pub struct QqConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_token_base_url")]
    pub token_base_url: String,
    pub app_id: String,
    pub client_secret: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub gateway: QqGatewayRuntimeConfig,
}

impl QqConfig {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        trim_string(&mut self.base_url);
        trim_string(&mut self.token_base_url);
        trim_string(&mut self.app_id);
        trim_string(&mut self.client_secret);
        self.gateway = self.gateway.normalized();
        self
    }
}

// Redact client_secret in Debug output
impl std::fmt::Debug for QqConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QqConfig")
            .field("base_url", &self.base_url)
            .field("token_base_url", &self.token_base_url)
            .field("app_id", &self.app_id)
            .field("client_secret", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("gateway", &self.gateway)
            .finish()
    }
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_token_base_url() -> String {
    DEFAULT_TOKEN_BASE_URL.to_string()
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[derive(Deserialize)]
pub struct AccessTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

impl std::fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────
// Gateway runtime and inbound policy configuration
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QqAccessPolicyMode {
    Open,
    Allowlist,
    Disabled,
}

impl QqAccessPolicyMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allowlist => "allowlist",
            Self::Disabled => "disabled",
        }
    }
}

impl Default for QqAccessPolicyMode {
    fn default() -> Self {
        Self::Open
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QqInboundPolicyConfig {
    pub dm_policy: QqAccessPolicyMode,
    pub dm_allow_from: Vec<String>,
    pub group_policy: QqAccessPolicyMode,
    pub group_allow_from: Vec<String>,
    pub group_require_mention: bool,
    pub bot_user_id: Option<String>,
    pub max_attachment_bytes: Option<u64>,
}

impl Default for QqInboundPolicyConfig {
    fn default() -> Self {
        Self {
            dm_policy: QqAccessPolicyMode::Open,
            dm_allow_from: Vec::new(),
            group_policy: QqAccessPolicyMode::Open,
            group_allow_from: Vec::new(),
            group_require_mention: true,
            bot_user_id: None,
            max_attachment_bytes: None,
        }
    }
}

impl QqInboundPolicyConfig {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        normalize_string_vec(&mut self.dm_allow_from);
        normalize_string_vec(&mut self.group_allow_from);
        trim_optional_string(&mut self.bot_user_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QqGatewayRuntimeConfig {
    pub enabled: bool,
    pub restore_session_id: Option<String>,
    pub restore_sequence: Option<u64>,
    pub heartbeat_interval_ms: u64,
    pub reconnect_backoff_ms: u64,
    pub max_reconnect_attempts: u32,
    pub dedupe_window_size: usize,
    pub max_queue_depth: usize,
    pub policy: QqInboundPolicyConfig,
}

impl Default for QqGatewayRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            restore_session_id: None,
            restore_sequence: None,
            heartbeat_interval_ms: 45_000,
            reconnect_backoff_ms: 1_000,
            max_reconnect_attempts: 5,
            dedupe_window_size: 1_024,
            max_queue_depth: 128,
            policy: QqInboundPolicyConfig::default(),
        }
    }
}

impl QqGatewayRuntimeConfig {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        trim_optional_string(&mut self.restore_session_id);
        self.policy = self.policy.normalized();
        self
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QqInboundPolicyDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
    pub routing: QqRouting,
    pub sender_id: Option<String>,
    pub target_id: Option<String>,
    pub mentioned_bot: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QqGatewayRuntimeSnapshot {
    pub enabled: bool,
    pub session_id: Option<String>,
    pub last_sequence: u64,
    pub heartbeat_interval_ms: u64,
    pub heartbeat_sent_count: u64,
    pub heartbeat_ack_count: u64,
    pub reconnect_attempts: u32,
    pub max_reconnect_attempts: u32,
    pub reconnect_backoff_ms: u64,
    pub queue_depth: usize,
    pub max_queue_depth: usize,
    pub dedupe_size: usize,
    pub dedupe_window_size: usize,
    pub accepted_events: u64,
    pub dropped_events: u64,
    pub duplicate_events: u64,
    pub stale_sequence_events: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QqGatewayEventProjection {
    pub accepted: bool,
    pub topic: &'static str,
    pub reason_code: &'static str,
    pub sequence: Option<u64>,
    pub event_id: Option<String>,
    pub normalized: Option<NormalizedQqEvent>,
    pub policy: Option<QqInboundPolicyDecision>,
    pub runtime: QqGatewayRuntimeSnapshot,
}

// ─────────────────────────────────────────────────────────────────
// Gateway event types (WebSocket event delivery)
// ─────────────────────────────────────────────────────────────────

/// QQ Bot gateway event payload received over WebSocket.
#[derive(Debug, Clone, Deserialize)]
pub struct QqGatewayEvent {
    /// Opcode (0 = dispatch, 1 = heartbeat, etc.)
    pub op: u8,
    /// Sequence number for resuming
    pub s: Option<u64>,
    /// Event type name (e.g., `"MESSAGE_CREATE"`, `"AT_MESSAGE_CREATE"`)
    pub t: Option<String>,
    /// Event data payload
    pub d: Option<serde_json::Value>,
    /// Event ID
    pub id: Option<String>,
}

/// QQ message event data extracted from gateway dispatch.
#[derive(Debug, Clone, Deserialize)]
pub struct QqMessageEvent {
    pub id: Option<String>,
    pub channel_id: Option<String>,
    pub guild_id: Option<String>,
    pub content: Option<String>,
    pub timestamp: Option<String>,
    pub author: Option<QqAuthor>,
    pub member: Option<serde_json::Value>,
    pub message_reference: Option<QqMessageReference>,
    pub attachments: Option<Vec<QqAttachment>>,
    /// Group open ID (present for group messages)
    pub group_openid: Option<String>,
    /// Group member open ID (present for group messages)
    pub group_member_openid: Option<String>,
}

/// Author information on a QQ message.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QqAuthor {
    pub id: Option<String>,
    pub username: Option<String>,
    pub bot: Option<bool>,
}

/// Quote/reply reference on a QQ message.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QqMessageReference {
    pub message_id: Option<String>,
}

/// Attachment on a QQ message.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QqAttachment {
    pub url: Option<String>,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub size: Option<u64>,
}

/// Routing classification for a QQ message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QqRouting {
    /// Guild channel message
    Channel,
    /// Group chat message
    Group,
    /// Consumer-to-consumer (private) message
    C2c,
}

impl QqRouting {
    /// Determine routing from the gateway event type string.
    #[must_use]
    pub fn from_event_type(event_type: &str) -> Option<Self> {
        match event_type {
            "MESSAGE_CREATE" | "AT_MESSAGE_CREATE" => Some(Self::Channel),
            "GROUP_AT_MESSAGE_CREATE" | "GROUP_MESSAGE_CREATE" => Some(Self::Group),
            "C2C_MESSAGE_CREATE" => Some(Self::C2c),
            _ => None,
        }
    }

    /// String representation for serialization.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Group => "group",
            Self::C2c => "c2c",
        }
    }
}

impl std::fmt::Display for QqRouting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalized QQ event with routing, quote context, and attachment detection.
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedQqEvent {
    /// The original gateway event type (e.g., `"AT_MESSAGE_CREATE"`)
    pub event_type: String,
    /// Message ID
    pub message_id: Option<String>,
    /// Channel ID (guild channel messages)
    pub channel_id: Option<String>,
    /// Guild ID (guild channel messages)
    pub guild_id: Option<String>,
    /// Group open ID (group messages)
    pub group_id: Option<String>,
    /// Sender ID (author ID or group member open ID)
    pub sender_id: Option<String>,
    /// Sender display name
    pub sender_name: Option<String>,
    /// Message text content
    pub text: Option<String>,
    /// ISO timestamp of the message
    pub timestamp: Option<String>,
    /// Whether this message is a reply to another message
    pub is_reply: bool,
    /// The message ID being replied to, if any
    pub reply_to: Option<String>,
    /// Whether the message has attachments
    pub has_attachments: bool,
    /// Routing classification
    pub routing: QqRouting,
    /// Raw event data for pass-through
    pub raw: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_defaults() {
        let json = r#"{
            "app_id": "test_id",
            "client_secret": "test_secret"
        }"#;
        let config: QqConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.token_base_url, DEFAULT_TOKEN_BASE_URL);
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.app_id, "test_id");
        assert_eq!(config.client_secret, "test_secret");
    }

    #[test]
    fn config_debug_redacts_secret() {
        let json = r#"{
            "app_id": "myid",
            "client_secret": "super_secret_value"
        }"#;
        let config: QqConfig = serde_json::from_str(json).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_value"));
        assert!(debug.contains("myid"));
    }

    #[test]
    fn config_with_custom_urls() {
        let json = r#"{
            "base_url": "http://localhost:8080",
            "token_base_url": "http://localhost:8081",
            "app_id": "app1",
            "client_secret": "sec1",
            "request_timeout_ms": 5000
        }"#;
        let config: QqConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, "http://localhost:8080");
        assert_eq!(config.token_base_url, "http://localhost:8081");
        assert_eq!(config.request_timeout_ms, 5000);
    }

    #[test]
    fn access_token_response_deserializes() {
        let json = r#"{"access_token": "tok_abc", "expires_in": 7200}"#;
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok_abc");
        assert_eq!(resp.expires_in, 7200);
    }

    #[test]
    fn access_token_response_defaults() {
        let json = r"{}";
        let resp: AccessTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "");
        assert_eq!(resp.expires_in, 0);
    }

    #[test]
    fn access_token_response_debug_redacts_token() {
        let resp = AccessTokenResponse {
            access_token: "super_secret_token_value".into(),
            expires_in: 7200,
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_token_value"));
        assert!(debug.contains("7200"));
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(OP_SEND_CHANNEL, "qq.messages.send_channel");
        assert_eq!(OP_SEND_GROUP, "qq.messages.send_group");
        assert_eq!(OP_SEND_C2C, "qq.messages.send_c2c");
        assert_eq!(OP_GET_GATEWAY, "qq.gateway.get");
        assert_eq!(OP_HEALTH, "qq.health");
        assert_eq!(OP_EVENTS_NORMALIZE, "qq.events.normalize");
        assert_eq!(CAP_MESSAGES_WRITE, "qq.messages.write");
        assert_eq!(CAP_GATEWAY_READ, "qq.gateway.read");
        assert_eq!(CAP_HEALTH_READ, "qq.health.read");
        assert_eq!(CAP_EVENTS_READ, "qq.events.read");
    }

    // ─── Gateway event type tests ───────────────────────────────

    #[test]
    fn gateway_event_deserializes_dispatch() {
        let json = r#"{
            "op": 0,
            "s": 42,
            "t": "MESSAGE_CREATE",
            "d": {"id": "msg-1", "content": "hello"},
            "id": "evt-1"
        }"#;
        let event: QqGatewayEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.op, 0);
        assert_eq!(event.s, Some(42));
        assert_eq!(event.t.as_deref(), Some("MESSAGE_CREATE"));
        assert!(event.d.is_some());
        assert_eq!(event.id.as_deref(), Some("evt-1"));
    }

    #[test]
    fn gateway_event_deserializes_heartbeat() {
        let json = r#"{"op": 1}"#;
        let event: QqGatewayEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.op, 1);
        assert!(event.s.is_none());
        assert!(event.t.is_none());
        assert!(event.d.is_none());
        assert!(event.id.is_none());
    }

    #[test]
    fn message_event_deserializes_channel_message() {
        let json = r#"{
            "id": "msg-1",
            "channel_id": "ch-1",
            "guild_id": "guild-1",
            "content": "hello world",
            "timestamp": "2026-03-23T12:00:00Z",
            "author": {"id": "user-1", "username": "Alice", "bot": false},
            "attachments": [{"url": "https://example.com/file.png", "filename": "file.png", "content_type": "image/png", "size": 1024}]
        }"#;
        let msg: QqMessageEvent = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id.as_deref(), Some("msg-1"));
        assert_eq!(msg.channel_id.as_deref(), Some("ch-1"));
        assert_eq!(msg.guild_id.as_deref(), Some("guild-1"));
        assert_eq!(msg.content.as_deref(), Some("hello world"));
        let author = msg.author.unwrap();
        assert_eq!(author.id.as_deref(), Some("user-1"));
        assert_eq!(author.username.as_deref(), Some("Alice"));
        assert_eq!(author.bot, Some(false));
        let attachments = msg.attachments.unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].filename.as_deref(), Some("file.png"));
        assert_eq!(attachments[0].size, Some(1024));
    }

    #[test]
    fn message_event_deserializes_group_message() {
        let json = r#"{
            "id": "msg-2",
            "content": "group hello",
            "group_openid": "group-1",
            "group_member_openid": "member-1"
        }"#;
        let msg: QqMessageEvent = serde_json::from_str(json).unwrap();
        assert_eq!(msg.group_openid.as_deref(), Some("group-1"));
        assert_eq!(msg.group_member_openid.as_deref(), Some("member-1"));
        assert!(msg.channel_id.is_none());
        assert!(msg.guild_id.is_none());
    }

    #[test]
    fn message_event_with_reply_reference() {
        let json = r#"{
            "id": "msg-3",
            "content": "replying",
            "message_reference": {"message_id": "msg-original"}
        }"#;
        let msg: QqMessageEvent = serde_json::from_str(json).unwrap();
        let reference = msg.message_reference.unwrap();
        assert_eq!(reference.message_id.as_deref(), Some("msg-original"));
    }

    #[test]
    fn message_event_minimal() {
        let json = r"{}";
        let msg: QqMessageEvent = serde_json::from_str(json).unwrap();
        assert!(msg.id.is_none());
        assert!(msg.content.is_none());
        assert!(msg.author.is_none());
        assert!(msg.attachments.is_none());
        assert!(msg.message_reference.is_none());
    }

    // ─── Routing tests ──────────────────────────────────────────

    #[test]
    fn routing_from_channel_event_types() {
        assert_eq!(
            QqRouting::from_event_type("MESSAGE_CREATE"),
            Some(QqRouting::Channel)
        );
        assert_eq!(
            QqRouting::from_event_type("AT_MESSAGE_CREATE"),
            Some(QqRouting::Channel)
        );
    }

    #[test]
    fn routing_from_group_event_types() {
        assert_eq!(
            QqRouting::from_event_type("GROUP_AT_MESSAGE_CREATE"),
            Some(QqRouting::Group)
        );
        assert_eq!(
            QqRouting::from_event_type("GROUP_MESSAGE_CREATE"),
            Some(QqRouting::Group)
        );
    }

    #[test]
    fn routing_from_c2c_event_type() {
        assert_eq!(
            QqRouting::from_event_type("C2C_MESSAGE_CREATE"),
            Some(QqRouting::C2c)
        );
    }

    #[test]
    fn routing_unknown_event_type_returns_none() {
        assert_eq!(QqRouting::from_event_type("READY"), None);
        assert_eq!(QqRouting::from_event_type("GUILD_CREATE"), None);
        assert_eq!(QqRouting::from_event_type(""), None);
    }

    #[test]
    fn routing_as_str() {
        assert_eq!(QqRouting::Channel.as_str(), "channel");
        assert_eq!(QqRouting::Group.as_str(), "group");
        assert_eq!(QqRouting::C2c.as_str(), "c2c");
    }

    #[test]
    fn routing_display() {
        assert_eq!(format!("{}", QqRouting::Channel), "channel");
        assert_eq!(format!("{}", QqRouting::Group), "group");
        assert_eq!(format!("{}", QqRouting::C2c), "c2c");
    }

    #[test]
    fn routing_serializes_lowercase() {
        let json = serde_json::to_string(&QqRouting::Channel).unwrap();
        assert_eq!(json, r#""channel""#);
        let json = serde_json::to_string(&QqRouting::C2c).unwrap();
        assert_eq!(json, r#""c2c""#);
    }

    #[test]
    fn routing_roundtrips() {
        for routing in [QqRouting::Channel, QqRouting::Group, QqRouting::C2c] {
            let json = serde_json::to_string(&routing).unwrap();
            let back: QqRouting = serde_json::from_str(&json).unwrap();
            assert_eq!(routing, back);
        }
    }

    #[test]
    fn attachment_serializes() {
        let att = QqAttachment {
            url: Some("https://example.com/f.png".into()),
            filename: Some("f.png".into()),
            content_type: Some("image/png".into()),
            size: Some(2048),
        };
        let json = serde_json::to_value(&att).unwrap();
        assert_eq!(json["url"], "https://example.com/f.png");
        assert_eq!(json["size"], 2048);
    }

    #[test]
    fn normalized_event_serializes() {
        let event = NormalizedQqEvent {
            event_type: "AT_MESSAGE_CREATE".into(),
            message_id: Some("msg-1".into()),
            channel_id: Some("ch-1".into()),
            guild_id: Some("guild-1".into()),
            group_id: None,
            sender_id: Some("user-1".into()),
            sender_name: Some("Alice".into()),
            text: Some("hello".into()),
            timestamp: Some("2026-03-23T12:00:00Z".into()),
            is_reply: false,
            reply_to: None,
            has_attachments: false,
            routing: QqRouting::Channel,
            raw: serde_json::json!({}),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "AT_MESSAGE_CREATE");
        assert_eq!(json["routing"], "channel");
        assert_eq!(json["is_reply"], false);
        assert_eq!(json["has_attachments"], false);
        assert_eq!(json["sender_name"], "Alice");
    }

    #[test]
    fn normalized_event_with_reply_serializes() {
        let event = NormalizedQqEvent {
            event_type: "MESSAGE_CREATE".into(),
            message_id: Some("msg-2".into()),
            channel_id: Some("ch-1".into()),
            guild_id: None,
            group_id: None,
            sender_id: Some("user-2".into()),
            sender_name: None,
            text: Some("reply text".into()),
            timestamp: None,
            is_reply: true,
            reply_to: Some("msg-1".into()),
            has_attachments: true,
            routing: QqRouting::Channel,
            raw: serde_json::json!({"id": "msg-2"}),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["is_reply"], true);
        assert_eq!(json["reply_to"], "msg-1");
        assert_eq!(json["has_attachments"], true);
    }
}
