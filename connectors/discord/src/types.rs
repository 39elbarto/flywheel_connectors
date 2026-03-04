//! Discord API types.

use serde::{Deserialize, Serialize};

/// Discord user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,

    /// Username
    pub username: String,

    /// Discriminator (legacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,

    /// Global display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_name: Option<String>,

    /// Avatar hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,

    /// Whether this is a bot
    #[serde(default)]
    pub bot: bool,
}

/// Discord guild (server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guild {
    /// Guild ID
    pub id: String,

    /// Guild name
    pub name: String,

    /// Icon hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// Owner ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

/// Discord channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    /// Channel ID
    pub id: String,

    /// Channel type
    #[serde(rename = "type")]
    pub channel_type: i32,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,

    /// Channel name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Topic
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

/// Discord message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message ID
    pub id: String,

    /// Channel ID
    pub channel_id: String,

    /// Author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<User>,

    /// Message content
    pub content: String,

    /// Timestamp
    pub timestamp: String,

    /// Whether this message is TTS
    #[serde(default)]
    pub tts: bool,

    /// Whether this mentions everyone
    #[serde(default)]
    pub mention_everyone: bool,

    /// Attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,

    /// Embeds
    #[serde(default)]
    pub embeds: Vec<Embed>,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
}

/// Discord attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID
    pub id: String,

    /// Filename
    pub filename: String,

    /// File size
    pub size: u64,

    /// URL
    pub url: String,

    /// Proxy URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,

    /// Content type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Discord embed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Embed {
    /// Title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Color
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<u32>,

    /// Fields
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<EmbedField>,

    /// Footer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<EmbedFooter>,

    /// Image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<EmbedImage>,

    /// Thumbnail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<EmbedThumbnail>,

    /// Author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<EmbedAuthor>,
}

/// Embed field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedField {
    /// Field name
    pub name: String,

    /// Field value
    pub value: String,

    /// Inline display
    #[serde(default)]
    pub inline: bool,
}

/// Embed footer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedFooter {
    /// Footer text
    pub text: String,

    /// Icon URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Embed image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedImage {
    /// Image URL
    pub url: String,
}

/// Embed thumbnail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedThumbnail {
    /// Thumbnail URL
    pub url: String,
}

/// Embed author.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedAuthor {
    /// Author name
    pub name: String,

    /// Author URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Icon URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Gateway event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayPayload {
    /// Opcode
    pub op: i32,

    /// Event data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<serde_json::Value>,

    /// Sequence number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,

    /// Event name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

/// Gateway identify payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayIdentify {
    /// Bot token
    pub token: String,

    /// Gateway intents
    pub intents: u64,

    /// Connection properties
    pub properties: GatewayProperties,

    /// Shard info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard: Option<[u32; 2]>,
}

/// Gateway connection properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProperties {
    /// OS
    pub os: String,

    /// Browser
    pub browser: String,

    /// Device
    pub device: String,
}

/// Gateway ready event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayReady {
    /// API version
    pub v: i32,

    /// Bot user
    pub user: User,

    /// Session ID
    pub session_id: String,

    /// Resume gateway URL
    pub resume_gateway_url: String,

    /// Guilds (unavailable)
    #[serde(default)]
    pub guilds: Vec<serde_json::Value>,
}

/// Gateway hello event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayHello {
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval: u64,
}

/// Gateway resume payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResume {
    /// Bot token
    pub token: String,
    /// Session ID from READY event
    pub session_id: String,
    /// Last sequence number received
    pub seq: u64,
}

/// Create message request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateMessage {
    /// Message content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// TTS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tts: Option<bool>,

    /// Embeds
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embeds: Vec<Embed>,

    /// Message reference (for replies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_reference: Option<MessageReference>,
}

/// Message reference for replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReference {
    /// Message ID to reply to
    pub message_id: String,

    /// Channel ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: "123".to_string(),
            username: "testbot".to_string(),
            discriminator: Some("0001".to_string()),
            global_name: Some("Test Bot".to_string()),
            avatar: None,
            bot: true,
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "123");
        assert!(back.bot);
    }

    #[test]
    fn user_minimal_deserialize() {
        let json = r#"{"id":"456","username":"human"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, "456");
        assert!(!user.bot); // default false
        assert!(user.discriminator.is_none());
    }

    // ---- Guild ----

    #[test]
    fn guild_serde_roundtrip() {
        let guild = Guild {
            id: "g1".to_string(),
            name: "Test Server".to_string(),
            icon: Some("abc".to_string()),
            owner_id: Some("123".to_string()),
        };
        let json = serde_json::to_string(&guild).unwrap();
        let back: Guild = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Test Server");
    }

    // ---- Channel ----

    #[test]
    fn channel_serde_roundtrip() {
        let channel = Channel {
            id: "ch1".to_string(),
            channel_type: 0,
            guild_id: Some("g1".to_string()),
            name: Some("general".to_string()),
            topic: Some("Welcome!".to_string()),
        };
        let json = serde_json::to_string(&channel).unwrap();
        assert!(json.contains("\"type\":0"));
        let back: Channel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.channel_type, 0);
    }

    // ---- Message ----

    #[test]
    fn message_serde_with_defaults() {
        let json = json!({
            "id": "m1",
            "channel_id": "ch1",
            "content": "Hello!",
            "timestamp": "2026-03-03T00:00:00Z"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.id, "m1");
        assert!(!msg.tts);
        assert!(!msg.mention_everyone);
        assert!(msg.attachments.is_empty());
        assert!(msg.embeds.is_empty());
        assert!(msg.author.is_none());
    }

    #[test]
    fn message_full_roundtrip() {
        let msg = Message {
            id: "m2".to_string(),
            channel_id: "ch1".to_string(),
            author: Some(User {
                id: "u1".to_string(),
                username: "bot".to_string(),
                discriminator: None,
                global_name: None,
                avatar: None,
                bot: true,
            }),
            content: "Test".to_string(),
            timestamp: "2026-03-03T00:00:00Z".to_string(),
            tts: false,
            mention_everyone: false,
            attachments: vec![],
            embeds: vec![],
            guild_id: Some("g1".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "m2");
        assert!(back.author.unwrap().bot);
    }

    // ---- Embed ----

    #[test]
    fn embed_default() {
        let embed = Embed::default();
        assert!(embed.title.is_none());
        assert!(embed.fields.is_empty());
        assert!(embed.color.is_none());
    }

    #[test]
    fn embed_full_serde() {
        let embed = Embed {
            title: Some("Title".to_string()),
            description: Some("Desc".to_string()),
            url: None,
            color: Some(0xFF_0000),
            fields: vec![EmbedField {
                name: "Field".to_string(),
                value: "Value".to_string(),
                inline: true,
            }],
            footer: Some(EmbedFooter {
                text: "Footer".to_string(),
                icon_url: None,
            }),
            image: Some(EmbedImage { url: "https://example.com/img.png".to_string() }),
            thumbnail: None,
            author: Some(EmbedAuthor {
                name: "Author".to_string(),
                url: None,
                icon_url: None,
            }),
        };
        let json = serde_json::to_string(&embed).unwrap();
        let back: Embed = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title.as_deref(), Some("Title"));
        assert_eq!(back.color, Some(0xFF_0000));
        assert_eq!(back.fields.len(), 1);
        assert!(back.fields[0].inline);
    }

    // ---- Attachment ----

    #[test]
    fn attachment_serde() {
        let att = Attachment {
            id: "a1".to_string(),
            filename: "test.txt".to_string(),
            size: 1024,
            url: "https://cdn.example.com/test.txt".to_string(),
            proxy_url: None,
            content_type: Some("text/plain".to_string()),
        };
        let json = serde_json::to_string(&att).unwrap();
        let back: Attachment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size, 1024);
    }

    // ---- GatewayPayload ----

    #[test]
    fn gateway_payload_dispatch_serde() {
        let payload = GatewayPayload {
            op: 0,
            d: Some(json!({"content": "hello"})),
            s: Some(42),
            t: Some("MESSAGE_CREATE".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: GatewayPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.op, 0);
        assert_eq!(back.s, Some(42));
        assert_eq!(back.t.as_deref(), Some("MESSAGE_CREATE"));
    }

    #[test]
    fn gateway_payload_heartbeat() {
        let payload = GatewayPayload {
            op: 1,
            d: Some(json!(42)),
            s: None,
            t: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("\"s\""));
        assert!(!json.contains("\"t\""));
    }

    // ---- GatewayHello ----

    #[test]
    fn gateway_hello_serde() {
        let hello = GatewayHello { heartbeat_interval: 41250 };
        let json = serde_json::to_string(&hello).unwrap();
        let back: GatewayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back.heartbeat_interval, 41250);
    }

    // ---- GatewayResume ----

    #[test]
    fn gateway_resume_serde() {
        let resume = GatewayResume {
            token: "tok".to_string(),
            session_id: "sess".to_string(),
            seq: 100,
        };
        let json = serde_json::to_string(&resume).unwrap();
        let back: GatewayResume = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seq, 100);
    }

    // ---- CreateMessage ----

    #[test]
    fn create_message_default() {
        let msg = CreateMessage::default();
        assert!(msg.content.is_none());
        assert!(msg.embeds.is_empty());
        assert!(msg.message_reference.is_none());
    }

    #[test]
    fn create_message_with_reply() {
        let msg = CreateMessage {
            content: Some("Reply".to_string()),
            tts: None,
            embeds: vec![],
            message_reference: Some(MessageReference {
                message_id: "m1".to_string(),
                channel_id: None,
                guild_id: None,
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("message_reference"));
        let back: CreateMessage = serde_json::from_str(&json).unwrap();
        assert!(back.message_reference.is_some());
    }
}
