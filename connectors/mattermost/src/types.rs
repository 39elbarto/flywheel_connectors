//! Mattermost API request and response types.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Mattermost connector configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct MattermostConfig {
    /// Base URL of the Mattermost server (e.g., `https://mattermost.example.com`).
    pub base_url: String,
    /// Personal access token or bot token.
    #[serde(default)]
    pub token: Option<String>,
    /// Credential ID for egress-proxy injection.
    #[serde(default)]
    pub credential_id: Option<String>,
    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl std::fmt::Debug for MattermostConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MattermostConfig")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("credential_id", &self.credential_id)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

const fn default_timeout_ms() -> u64 {
    30_000
}

/// Authentication mode.
#[derive(Clone)]
pub enum MattermostAuth {
    /// Direct token (personal access token or bot token).
    Token(String),
    /// Credential ID for egress proxy injection.
    CredentialId(String),
}

impl std::fmt::Debug for MattermostAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// A Mattermost user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub roles: String,
}

/// A Mattermost team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type", default)]
    pub team_type: String,
}

/// A Mattermost channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    #[serde(default)]
    pub team_id: String,
    #[serde(rename = "type", default)]
    pub channel_type: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub delete_at: i64,
}

/// A Mattermost post (message).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post {
    pub id: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub root_id: String,
    #[serde(default)]
    pub create_at: i64,
    #[serde(default)]
    pub update_at: i64,
    #[serde(default)]
    pub delete_at: i64,
    #[serde(rename = "type", default)]
    pub post_type: String,
    #[serde(default)]
    pub props: serde_json::Value,
    #[serde(default)]
    pub file_ids: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Request for creating a post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePostRequest {
    pub channel_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub props: Option<serde_json::Value>,
}

/// Request for creating or retrieving a direct channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDirectChannelRequest {
    pub user_ids: Vec<String>,
}

/// Request for saving a reaction on a post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReactionRequest {
    pub user_id: String,
    pub post_id: String,
    pub emoji_name: String,
}

/// Request for removing a reaction from a post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteReactionRequest {
    pub user_id: String,
    pub post_id: String,
    pub emoji_name: String,
}

/// Paginated post list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostList {
    #[serde(default)]
    pub order: Vec<String>,
    #[serde(default)]
    pub posts: std::collections::HashMap<String, Post>,
    #[serde(default)]
    pub next_post_id: String,
    #[serde(default)]
    pub prev_post_id: String,
    #[serde(default)]
    pub first_inaccessible_post_time: i64,
    #[serde(default)]
    pub has_next: bool,
    #[serde(default)]
    pub matches: std::collections::HashMap<String, Vec<String>>,
}

/// Request for fetching a thread rooted at a post.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetThreadRequest {
    pub post_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_post: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_create_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_update_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_fetch_threads: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapsed_threads: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapsed_threads_extended: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates_only: Option<bool>,
}

/// Search posts request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPostsRequest {
    pub terms: String,
    #[serde(default)]
    pub is_or_search: bool,
}

/// Mattermost file metadata returned by the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: String,
    #[serde(rename = "user_id", default)]
    pub creator_id: String,
    #[serde(default)]
    pub post_id: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(default)]
    pub create_at: i64,
    #[serde(default)]
    pub update_at: i64,
    #[serde(default)]
    pub delete_at: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub extension: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub width: i32,
    #[serde(default)]
    pub height: i32,
    #[serde(default)]
    pub has_preview_image: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub remote_id: Option<String>,
}

/// Mattermost reaction payload embedded in websocket events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub post_id: String,
    #[serde(default)]
    pub emoji_name: String,
    #[serde(default)]
    pub create_at: i64,
}

/// Thread metadata embedded in websocket thread update events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadResponse {
    pub id: String,
    #[serde(default)]
    pub reply_count: i64,
    #[serde(default)]
    pub last_reply_at: i64,
    #[serde(default)]
    pub last_viewed_at: i64,
    #[serde(default)]
    pub unread_replies: i64,
    #[serde(default)]
    pub unread_mentions: i64,
    #[serde(default)]
    pub post: Option<Post>,
}

/// Broadcast scope attached to a websocket event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MattermostWebSocketBroadcast {
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(default)]
    pub team_id: String,
}

/// Server-sent Mattermost websocket frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MattermostWebSocketMessage {
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub broadcast: MattermostWebSocketBroadcast,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub seq_reply: Option<u64>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error: Option<Value>,
}

/// File download payload returned by the connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownload {
    pub file_id: String,
    pub content_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub size_bytes: usize,
}

/// Request for uploading a single file into Mattermost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFileRequest {
    pub channel_id: String,
    pub filename: String,
    pub content_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

impl UploadFileRequest {
    /// Decode the base64 file body into raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the content is not valid base64.
    pub fn decode_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.content_base64)
    }
}

/// Mattermost file upload response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFileResponse {
    #[serde(default)]
    pub file_infos: Vec<FileInfo>,
    #[serde(default)]
    pub client_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserialize_minimal() {
        let json = r#"{"base_url": "https://mm.example.com"}"#;
        let config: MattermostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, "https://mm.example.com");
        assert!(config.token.is_none());
        assert_eq!(config.request_timeout_ms, 30_000);
    }

    #[test]
    fn config_deserialize_full() {
        let json = r#"{"base_url": "https://mm.example.com", "token": "tok_abc", "request_timeout_ms": 5000}"#;
        let config: MattermostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.token.as_deref(), Some("tok_abc"));
        assert_eq!(config.request_timeout_ms, 5000);
    }

    #[test]
    fn user_deserialize() {
        let json = r#"{"id": "u1", "username": "admin", "email": "admin@mm.local"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, "u1");
        assert_eq!(user.username, "admin");
    }

    #[test]
    fn team_deserialize() {
        let json =
            r#"{"id": "t1", "name": "engineering", "display_name": "Engineering", "type": "O"}"#;
        let team: Team = serde_json::from_str(json).unwrap();
        assert_eq!(team.team_type, "O");
    }

    #[test]
    fn channel_deserialize() {
        let json = r#"{"id": "c1", "team_id": "t1", "type": "O", "display_name": "General", "name": "general"}"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert_eq!(ch.channel_type, "O");
    }

    #[test]
    fn post_deserialize() {
        let json = r#"{"id": "p1", "channel_id": "c1", "user_id": "u1", "message": "Hello!", "create_at": 1700000000000, "file_ids": ["f1"]}"#;
        let post: Post = serde_json::from_str(json).unwrap();
        assert_eq!(post.message, "Hello!");
        assert_eq!(post.create_at, 1_700_000_000_000);
        assert_eq!(post.file_ids, vec!["f1"]);
    }

    #[test]
    fn create_post_request_serialize() {
        let req = CreatePostRequest {
            channel_id: "c1".into(),
            message: "test message".into(),
            root_id: None,
            file_ids: None,
            props: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["channel_id"], "c1");
        assert!(json.get("root_id").is_none());
        assert!(json.get("file_ids").is_none());
    }

    #[test]
    fn create_post_request_with_thread() {
        let req = CreatePostRequest {
            channel_id: "c1".into(),
            message: "reply".into(),
            root_id: Some("p_root".into()),
            file_ids: None,
            props: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["root_id"], "p_root");
    }

    #[test]
    fn create_post_request_with_file_ids() {
        let req = CreatePostRequest {
            channel_id: "c1".into(),
            message: "attachment".into(),
            root_id: None,
            file_ids: Some(vec!["file-1".into(), "file-2".into()]),
            props: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["file_ids"][0], "file-1");
        assert_eq!(json["file_ids"][1], "file-2");
    }

    #[test]
    fn create_direct_channel_request_serializes_user_ids() {
        let req = CreateDirectChannelRequest {
            user_ids: vec!["u1".into(), "u2".into()],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_ids"][0], "u1");
        assert_eq!(json["user_ids"][1], "u2");
    }

    #[test]
    fn create_reaction_request_serializes() {
        let req = CreateReactionRequest {
            user_id: "u1".into(),
            post_id: "p1".into(),
            emoji_name: "thumbsup".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_id"], "u1");
        assert_eq!(json["post_id"], "p1");
        assert_eq!(json["emoji_name"], "thumbsup");
    }

    #[test]
    fn delete_reaction_request_serializes() {
        let req = DeleteReactionRequest {
            user_id: "u1".into(),
            post_id: "p1".into(),
            emoji_name: "thumbsup".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_id"], "u1");
        assert_eq!(json["post_id"], "p1");
        assert_eq!(json["emoji_name"], "thumbsup");
    }

    #[test]
    fn post_list_deserialize() {
        let json = r#"{"order": ["p1"], "posts": {"p1": {"id": "p1", "message": "hi"}}}"#;
        let list: PostList = serde_json::from_str(json).unwrap();
        assert_eq!(list.order.len(), 1);
        assert!(list.posts.contains_key("p1"));
        assert!(list.next_post_id.is_empty());
        assert!(!list.has_next);
    }

    #[test]
    fn post_list_preserves_thread_and_search_metadata() {
        let json = r#"{
            "order": ["p1"],
            "posts": {"p1": {"id": "p1", "message": "hi"}},
            "next_post_id": "p2",
            "prev_post_id": "p0",
            "first_inaccessible_post_time": 42,
            "has_next": true,
            "matches": {"p1": ["message"]}
        }"#;
        let list: PostList = serde_json::from_str(json).unwrap();
        assert_eq!(list.next_post_id, "p2");
        assert_eq!(list.prev_post_id, "p0");
        assert_eq!(list.first_inaccessible_post_time, 42);
        assert!(list.has_next);
        assert_eq!(list.matches.get("p1"), Some(&vec![String::from("message")]));
    }

    #[test]
    fn search_request_serialize() {
        let req = SearchPostsRequest {
            terms: "test query".into(),
            is_or_search: true,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["terms"], "test query");
        assert_eq!(json["is_or_search"], true);
    }

    #[test]
    fn file_info_deserialize() {
        let json = r#"{"id":"f1","user_id":"u1","post_id":"p1","channel_id":"c1","create_at":1,"update_at":2,"name":"report.txt","extension":"txt","size":42,"mime_type":"text/plain","archived":false}"#;
        let file: FileInfo = serde_json::from_str(json).unwrap();
        assert_eq!(file.id, "f1");
        assert_eq!(file.creator_id, "u1");
        assert_eq!(file.name, "report.txt");
    }

    #[test]
    fn thread_response_deserialize() {
        let json = r#"{"id":"root1","reply_count":3,"last_reply_at":123,"post":{"id":"root1","channel_id":"c1","message":"root"}}"#;
        let thread: ThreadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(thread.id, "root1");
        assert_eq!(thread.reply_count, 3);
        assert_eq!(thread.post.as_ref().unwrap().channel_id, "c1");
    }

    #[test]
    fn get_thread_request_serialize() {
        let request = GetThreadRequest {
            post_id: "root1".into(),
            per_page: Some(30),
            from_post: Some("cursor1".into()),
            from_create_at: Some(11),
            from_update_at: Some(12),
            direction: Some("down".into()),
            skip_fetch_threads: Some(true),
            collapsed_threads: Some(true),
            collapsed_threads_extended: Some(false),
            updates_only: Some(true),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["post_id"], "root1");
        assert_eq!(json["per_page"], 30);
        assert_eq!(json["direction"], "down");
        assert_eq!(json["skip_fetch_threads"], true);
    }

    #[test]
    fn file_download_serialize() {
        let payload = FileDownload {
            file_id: "f1".into(),
            content_base64: "aGVsbG8=".into(),
            content_type: Some("text/plain".into()),
            size_bytes: 5,
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["file_id"], "f1");
        assert_eq!(json["content_base64"], "aGVsbG8=");
        assert_eq!(json["content_type"], "text/plain");
        assert_eq!(json["size_bytes"], 5);
    }

    #[test]
    fn upload_file_request_decodes_base64() {
        let request = UploadFileRequest {
            channel_id: "channel1".into(),
            filename: "hello.txt".into(),
            content_base64: "aGVsbG8=".into(),
            client_id: Some("client-1".into()),
            content_type: Some("text/plain".into()),
        };
        let bytes = request.decode_bytes().unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn upload_file_response_deserializes() {
        let json = r#"{
            "file_infos": [{"id":"f1","user_id":"u1","name":"report.txt","size":42}],
            "client_ids": ["client-1"]
        }"#;
        let response: UploadFileResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.file_infos.len(), 1);
        assert_eq!(response.file_infos[0].id, "f1");
        assert_eq!(response.client_ids, vec![String::from("client-1")]);
    }

    #[test]
    fn websocket_message_deserialize() {
        let json = r#"{"event":"posted","data":{"post":"{\"id\":\"p1\",\"channel_id\":\"c1\",\"user_id\":\"u1\",\"message\":\"hello\"}","sender_name":"alice"},"broadcast":{"channel_id":"c1","team_id":"t1","user_id":"u2"},"seq":44}"#;
        let message: MattermostWebSocketMessage = serde_json::from_str(json).unwrap();
        assert_eq!(message.event.as_deref(), Some("posted"));
        assert_eq!(message.broadcast.channel_id, "c1");
        assert_eq!(message.seq, Some(44));
    }
}
