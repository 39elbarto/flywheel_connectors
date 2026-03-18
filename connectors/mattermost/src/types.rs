//! Mattermost API request and response types.

use serde::{Deserialize, Serialize};

/// Mattermost connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

const fn default_timeout_ms() -> u64 {
    30_000
}

/// Authentication mode.
#[derive(Debug, Clone)]
pub enum MattermostAuth {
    /// Direct token (personal access token or bot token).
    Token(String),
    /// Credential ID for egress proxy injection.
    CredentialId(String),
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
}

/// Request for creating a post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePostRequest {
    pub channel_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub props: Option<serde_json::Value>,
}

/// Paginated post list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostList {
    #[serde(default)]
    pub order: Vec<String>,
    #[serde(default)]
    pub posts: std::collections::HashMap<String, Post>,
}

/// Search posts request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPostsRequest {
    pub terms: String,
    #[serde(default)]
    pub is_or_search: bool,
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
        let json = r#"{"id": "t1", "name": "engineering", "display_name": "Engineering", "type": "O"}"#;
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
        let json = r#"{"id": "p1", "channel_id": "c1", "user_id": "u1", "message": "Hello!", "create_at": 1700000000000}"#;
        let post: Post = serde_json::from_str(json).unwrap();
        assert_eq!(post.message, "Hello!");
        assert_eq!(post.create_at, 1_700_000_000_000);
    }

    #[test]
    fn create_post_request_serialize() {
        let req = CreatePostRequest {
            channel_id: "c1".into(),
            message: "test message".into(),
            root_id: None,
            props: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["channel_id"], "c1");
        assert!(json.get("root_id").is_none());
    }

    #[test]
    fn create_post_request_with_thread() {
        let req = CreatePostRequest {
            channel_id: "c1".into(),
            message: "reply".into(),
            root_id: Some("p_root".into()),
            props: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["root_id"], "p_root");
    }

    #[test]
    fn post_list_deserialize() {
        let json = r#"{"order": ["p1"], "posts": {"p1": {"id": "p1", "message": "hi"}}}"#;
        let list: PostList = serde_json::from_str(json).unwrap();
        assert_eq!(list.order.len(), 1);
        assert!(list.posts.contains_key("p1"));
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
}
