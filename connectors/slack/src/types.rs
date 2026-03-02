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
