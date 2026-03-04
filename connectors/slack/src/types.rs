//! Slack API types.

use serde::{Deserialize, Serialize};

/// Slack message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "type", default)]
    pub message_type: String,
    #[serde(default)]
    pub user: Option<String>,
    pub text: String,
    pub ts: String,
    #[serde(default)]
    pub thread_ts: Option<String>,
    #[serde(default)]
    pub reply_count: Option<u32>,
    #[serde(default)]
    pub reactions: Option<Vec<Reaction>>,
    #[serde(default)]
    pub files: Option<Vec<SlackFile>>,
    #[serde(default)]
    pub bot_id: Option<String>,
}

/// Slack reaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub name: String,
    pub count: u32,
    #[serde(default)]
    pub users: Vec<String>,
}

/// Slack channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Channel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub is_channel: bool,
    #[serde(default)]
    pub is_group: bool,
    #[serde(default)]
    pub is_im: bool,
    #[serde(default)]
    pub is_archived: bool,
    #[serde(default)]
    pub is_private: bool,
    #[serde(default)]
    pub num_members: u32,
    #[serde(default)]
    pub topic: Option<TopicPurpose>,
    #[serde(default)]
    pub purpose: Option<TopicPurpose>,
}

/// Slack channel topic or purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicPurpose {
    pub value: String,
    #[serde(default)]
    pub creator: String,
    #[serde(default)]
    pub last_set: u64,
}

/// Slack user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub real_name: Option<String>,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub profile: Option<UserProfile>,
}

/// Slack user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub image_48: Option<String>,
    #[serde(default)]
    pub status_text: Option<String>,
    #[serde(default)]
    pub status_emoji: Option<String>,
}

/// Slack file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackFile {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub mimetype: Option<String>,
    #[serde(default)]
    pub filetype: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub url_private: Option<String>,
    #[serde(default)]
    pub url_private_download: Option<String>,
}

/// Slack API envelope for responses.
#[derive(Debug, Clone, Deserialize)]
pub struct SlackApiResponse<T> {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub data: Option<T>,
}

/// Conversations.history response data.
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryData {
    pub messages: Vec<Message>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub response_metadata: Option<ResponseMetadata>,
}

/// Search response data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchData {
    pub messages: SearchMatches,
}

/// Search matches container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatches {
    pub total: u32,
    pub matches: Vec<Message>,
}

/// Channel list response data.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelListData {
    pub channels: Vec<Channel>,
    #[serde(default)]
    pub response_metadata: Option<ResponseMetadata>,
}

/// User info response data.
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfoData {
    pub user: User,
}

/// File upload response data.
#[derive(Debug, Clone, Deserialize)]
pub struct FileUploadData {
    pub file: SlackFile,
}

/// Topic set response data.
#[derive(Debug, Clone, Deserialize)]
pub struct TopicSetData {
    pub topic: String,
}

/// Post message response data.
#[derive(Debug, Clone, Deserialize)]
pub struct PostMessageData {
    pub channel: String,
    pub ts: String,
    pub message: Message,
}

/// Response metadata (pagination cursor).
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMetadata {
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Result of Slack `auth.test` — identifies the token holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTestInfo {
    pub url: String,
    pub team: String,
    pub user: String,
    pub team_id: String,
    pub user_id: String,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub is_enterprise_install: bool,
}

/// auth.test response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthTestData {
    pub url: String,
    pub team: String,
    pub user: String,
    pub team_id: String,
    pub user_id: String,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub is_enterprise_install: bool,
}

/// apps.connections.open response data for Socket Mode.
#[derive(Debug, Clone, Deserialize)]
pub struct SocketModeOpenData {
    pub url: String,
}

/// Audit receipt for side-effecting operations.
#[derive(Debug, Clone, Serialize)]
pub struct OperationReceipt {
    pub operation: String,
    pub effect: String,
    pub resource: String,
    pub timestamp: String,
}

/// Provisioning doctor report for readiness validation.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ready: bool,
    pub checks: Vec<DoctorCheck>,
}

/// A single doctor check result.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Message ----

    #[test]
    fn message_serde_roundtrip() {
        let msg = Message {
            message_type: "message".to_string(),
            user: Some("U123".to_string()),
            text: "Hello!".to_string(),
            ts: "1234567890.123456".to_string(),
            thread_ts: None,
            reply_count: None,
            reactions: None,
            files: None,
            bot_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.text, "Hello!");
        assert_eq!(back.user, Some("U123".to_string()));
    }

    #[test]
    fn message_deserialize_minimal() {
        let json = r#"{"text":"hi","ts":"123.456"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.text, "hi");
        assert!(msg.user.is_none());
        assert!(msg.reactions.is_none());
        assert!(msg.files.is_none());
    }

    // ---- Channel ----

    #[test]
    fn channel_serde_with_booleans() {
        let ch = Channel {
            id: "C123".to_string(),
            name: "general".to_string(),
            is_channel: true,
            is_group: false,
            is_im: false,
            is_archived: false,
            is_private: false,
            num_members: 42,
            topic: Some(TopicPurpose {
                value: "Welcome".to_string(),
                creator: "U001".to_string(),
                last_set: 1_000_000,
            }),
            purpose: None,
        };
        let json = serde_json::to_string(&ch).unwrap();
        let back: Channel = serde_json::from_str(&json).unwrap();
        assert!(back.is_channel);
        assert_eq!(back.num_members, 42);
        assert!(back.topic.is_some());
    }

    #[test]
    fn channel_deserialize_defaults() {
        let json = r#"{"id":"C1","name":"test"}"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert!(!ch.is_channel);
        assert!(!ch.is_archived);
        assert_eq!(ch.num_members, 0);
    }

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: "U123".to_string(),
            name: "testuser".to_string(),
            real_name: Some("Test User".to_string()),
            is_bot: false,
            is_admin: true,
            deleted: false,
            profile: Some(UserProfile {
                display_name: "Test".to_string(),
                email: Some("test@example.com".to_string()),
                image_48: None,
                status_text: None,
                status_emoji: None,
            }),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "U123");
        assert!(back.is_admin);
        assert!(back.profile.is_some());
    }

    #[test]
    fn user_deserialize_minimal() {
        let json = r#"{"id":"U1","text":"unused","name":"","real_name":null}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert!(!user.is_bot);
        assert!(!user.deleted);
        assert!(user.profile.is_none());
    }

    // ---- Reaction ----

    #[test]
    fn reaction_serde() {
        let reaction = Reaction {
            name: "thumbsup".to_string(),
            count: 5,
            users: vec!["U1".to_string(), "U2".to_string()],
        };
        let json = serde_json::to_string(&reaction).unwrap();
        let back: Reaction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count, 5);
        assert_eq!(back.users.len(), 2);
    }

    // ---- SlackFile ----

    #[test]
    fn slack_file_serde() {
        let file = SlackFile {
            id: "F123".to_string(),
            name: Some("report.pdf".to_string()),
            title: Some("Q1 Report".to_string()),
            mimetype: Some("application/pdf".to_string()),
            filetype: Some("pdf".to_string()),
            size: 1_048_576,
            url_private: Some("https://files.slack.com/...".to_string()),
            url_private_download: None,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: SlackFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size, 1_048_576);
    }

    // ---- SlackApiResponse ----

    #[test]
    fn slack_api_response_ok() {
        let json = r#"{"ok":true,"channel":"C1","ts":"123.456","message":{"text":"hi","ts":"123.456"}}"#;
        let resp: SlackApiResponse<PostMessageData> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert!(resp.error.is_none());
    }

    #[test]
    fn slack_api_response_error() {
        let json = r#"{"ok":false,"error":"channel_not_found"}"#;
        let resp: SlackApiResponse<PostMessageData> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("channel_not_found"));
    }

    // ---- AuthTestInfo ----

    #[test]
    fn auth_test_info_serde() {
        let info = AuthTestInfo {
            url: "https://team.slack.com/".to_string(),
            team: "Test Team".to_string(),
            user: "testbot".to_string(),
            team_id: "T123".to_string(),
            user_id: "U123".to_string(),
            bot_id: Some("B123".to_string()),
            is_enterprise_install: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: AuthTestInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.team_id, "T123");
        assert_eq!(back.bot_id, Some("B123".to_string()));
    }

    // ---- SearchData ----

    #[test]
    fn search_data_serde() {
        let data = SearchData {
            messages: SearchMatches {
                total: 1,
                matches: vec![Message {
                    message_type: "message".to_string(),
                    user: Some("U1".to_string()),
                    text: "found it".to_string(),
                    ts: "123.456".to_string(),
                    thread_ts: None,
                    reply_count: None,
                    reactions: None,
                    files: None,
                    bot_id: None,
                }],
            },
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: SearchData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.messages.total, 1);
        assert_eq!(back.messages.matches.len(), 1);
    }

    // ---- ResponseMetadata ----

    #[test]
    fn response_metadata_with_cursor() {
        let json = r#"{"next_cursor":"abc123"}"#;
        let meta: ResponseMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.next_cursor.as_deref(), Some("abc123"));
    }

    #[test]
    fn response_metadata_empty() {
        let json = r#"{}"#;
        let meta: ResponseMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.next_cursor.is_none());
    }

    // ---- OperationReceipt ----

    #[test]
    fn operation_receipt_serialize() {
        let receipt = OperationReceipt {
            operation: "post_message".to_string(),
            effect: "created".to_string(),
            resource: "message".to_string(),
            timestamp: "2026-03-03T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("post_message"));
    }

    // ---- DoctorReport ----

    #[test]
    fn doctor_report_serialize() {
        let report = DoctorReport {
            ready: true,
            checks: vec![DoctorCheck {
                name: "auth".to_string(),
                passed: true,
                message: "Token valid".to_string(),
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"ready\":true"));
        assert!(json.contains("\"passed\":true"));
    }
}
