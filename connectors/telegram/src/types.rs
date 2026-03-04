//! Telegram API types.
//!
//! Types definitions for Telegram Bot API objects.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

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
}
