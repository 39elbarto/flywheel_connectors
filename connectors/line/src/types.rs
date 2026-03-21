//! LINE Messaging API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Message types
// ─────────────────────────────────────────────────────────────────────────────

/// A LINE message object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image {
        #[serde(rename = "originalContentUrl")]
        original_content_url: String,
        #[serde(rename = "previewImageUrl")]
        preview_image_url: String,
    },
    #[serde(rename = "sticker")]
    Sticker {
        #[serde(rename = "packageId")]
        package_id: String,
        #[serde(rename = "stickerId")]
        sticker_id: String,
    },
}

/// Push message request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMessageRequest {
    pub to: String,
    pub messages: Vec<Message>,
}

/// Reply message request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyMessageRequest {
    #[serde(rename = "replyToken")]
    pub reply_token: String,
    pub messages: Vec<Message>,
}

/// Multicast message request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastRequest {
    pub to: Vec<String>,
    pub messages: Vec<Message>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response types
// ─────────────────────────────────────────────────────────────────────────────

/// Sent message response (LINE returns an empty 200 for most messaging ops).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentMessageResponse {
    #[serde(rename = "sentMessages", default)]
    pub sent_messages: Vec<SentMessageRef>,
}

/// Reference to a sent message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentMessageRef {
    pub id: String,
    #[serde(rename = "quoteToken", skip_serializing_if = "Option::is_none")]
    pub quote_token: Option<String>,
}

/// User profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "pictureUrl", skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
    #[serde(rename = "statusMessage", skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Group summary (profile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "groupName")]
    pub group_name: String,
    #[serde(rename = "pictureUrl", skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
}

/// Group member list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembersResponse {
    #[serde(rename = "memberIds")]
    pub member_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Rich Menu types
// ─────────────────────────────────────────────────────────────────────────────

/// Rich menu object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenu {
    #[serde(rename = "richMenuId", skip_serializing_if = "Option::is_none")]
    pub rich_menu_id: Option<String>,
    pub size: RichMenuSize,
    pub selected: bool,
    pub name: String,
    #[serde(rename = "chatBarText")]
    pub chat_bar_text: String,
    pub areas: Vec<RichMenuArea>,
}

/// Rich menu size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuSize {
    pub width: u32,
    pub height: u32,
}

/// Rich menu area.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuArea {
    pub bounds: RichMenuBounds,
    pub action: RichMenuAction,
}

/// Rich menu bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuBounds {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Rich menu action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Rich menu list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuListResponse {
    pub richmenus: Vec<RichMenu>,
}

/// Rich menu create response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuCreateResponse {
    #[serde(rename = "richMenuId")]
    pub rich_menu_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error response
// ─────────────────────────────────────────────────────────────────────────────

/// LINE API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub message: String,
    #[serde(default)]
    pub details: Vec<ApiErrorDetail>,
}

/// Individual error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_message_serialization() {
        let msg = Message::Text {
            text: "Hello!".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "Hello!");
    }

    #[test]
    fn sticker_message_serialization() {
        let msg = Message::Sticker {
            package_id: "446".into(),
            sticker_id: "1988".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "sticker");
        assert_eq!(json["packageId"], "446");
    }

    #[test]
    fn push_request_serialization() {
        let req = PushMessageRequest {
            to: "U1234".into(),
            messages: vec![Message::Text {
                text: "hi".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["to"], "U1234");
        assert_eq!(json["messages"][0]["type"], "text");
    }

    #[test]
    fn reply_request_serialization() {
        let req = ReplyMessageRequest {
            reply_token: "tok_abc".into(),
            messages: vec![Message::Text {
                text: "reply".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["replyToken"], "tok_abc");
    }

    #[test]
    fn multicast_request_serialization() {
        let req = MulticastRequest {
            to: vec!["U1".into(), "U2".into()],
            messages: vec![Message::Text {
                text: "broadcast".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["to"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn user_profile_deserialization() {
        let json = serde_json::json!({
            "displayName": "Test User",
            "userId": "U1234567890",
            "pictureUrl": "https://example.com/pic.jpg",
            "statusMessage": "Hello",
            "language": "en"
        });
        let profile: UserProfile = serde_json::from_value(json).unwrap();
        assert_eq!(profile.display_name, "Test User");
        assert_eq!(profile.user_id, "U1234567890");
    }

    #[test]
    fn group_summary_deserialization() {
        let json = serde_json::json!({
            "groupId": "C1234",
            "groupName": "Test Group",
            "pictureUrl": "https://example.com/group.jpg"
        });
        let summary: GroupSummary = serde_json::from_value(json).unwrap();
        assert_eq!(summary.group_id, "C1234");
    }

    #[test]
    fn group_members_deserialization() {
        let json = serde_json::json!({
            "memberIds": ["U1", "U2", "U3"],
            "next": "token123"
        });
        let members: GroupMembersResponse = serde_json::from_value(json).unwrap();
        assert_eq!(members.member_ids.len(), 3);
        assert_eq!(members.next, Some("token123".into()));
    }

    #[test]
    fn rich_menu_serialization() {
        let menu = RichMenu {
            rich_menu_id: None,
            size: RichMenuSize {
                width: 2500,
                height: 1686,
            },
            selected: false,
            name: "Test Menu".into(),
            chat_bar_text: "Tap here".into(),
            areas: vec![RichMenuArea {
                bounds: RichMenuBounds {
                    x: 0,
                    y: 0,
                    width: 2500,
                    height: 1686,
                },
                action: RichMenuAction {
                    action_type: "message".into(),
                    text: Some("hello".into()),
                    uri: None,
                    label: Some("Hello".into()),
                },
            }],
        };
        let json = serde_json::to_value(&menu).unwrap();
        assert_eq!(json["size"]["width"], 2500);
        assert_eq!(json["areas"][0]["action"]["type"], "message");
    }

    #[test]
    fn rich_menu_create_response_deserialization() {
        let json = serde_json::json!({ "richMenuId": "richmenu-abc123" });
        let resp: RichMenuCreateResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.rich_menu_id, "richmenu-abc123");
    }

    #[test]
    fn api_error_response_deserialization() {
        let json = serde_json::json!({
            "message": "Invalid reply token",
            "details": [{ "message": "token expired", "property": "replyToken" }]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Invalid reply token");
        assert_eq!(err.details.len(), 1);
    }

    #[test]
    fn image_message_serialization() {
        let msg = Message::Image {
            original_content_url: "https://example.com/img.jpg".into(),
            preview_image_url: "https://example.com/thumb.jpg".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "image");
        assert!(json["originalContentUrl"].as_str().is_some());
    }

    #[test]
    fn sent_message_response_deserialization() {
        let json = serde_json::json!({
            "sentMessages": [{ "id": "msg123", "quoteToken": "qt_abc" }]
        });
        let resp: SentMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.sent_messages.len(), 1);
        assert_eq!(resp.sent_messages[0].id, "msg123");
    }

    #[test]
    fn rich_menu_list_response_deserialization() {
        let json = serde_json::json!({
            "richmenus": [{
                "richMenuId": "rm1",
                "size": { "width": 2500, "height": 1686 },
                "selected": false,
                "name": "Menu 1",
                "chatBarText": "Open",
                "areas": []
            }]
        });
        let resp: RichMenuListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.richmenus.len(), 1);
    }

    #[test]
    fn user_profile_minimal_deserialization() {
        let json = serde_json::json!({
            "displayName": "User",
            "userId": "U999"
        });
        let profile: UserProfile = serde_json::from_value(json).unwrap();
        assert!(profile.picture_url.is_none());
        assert!(profile.status_message.is_none());
    }
}
