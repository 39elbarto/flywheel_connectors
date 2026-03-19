//! Microsoft Teams API types.
//!
//! Covers Graph API (teams, channels, messages) and Bot Framework activity types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Teams connector configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TeamsConfig {
    /// Microsoft Graph API base URL.
    #[serde(default = "default_graph_url")]
    pub graph_base_url: String,

    /// Bot Framework endpoint (for activity ingress).
    #[serde(default = "default_bot_url")]
    pub bot_service_url: String,

    /// Authentication configuration.
    pub auth: TeamsAuth,

    /// Tenant ID for multi-tenant apps.
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// HTTP retry configuration.
    #[serde(default)]
    pub retry: fcp_sdk::migration::HttpRetryConfig,

    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Authentication mode for Teams.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode")]
pub enum TeamsAuth {
    /// Bearer token (delegated permissions).
    #[serde(rename = "access_token")]
    AccessToken { access_token: String },

    /// Client credentials flow (app-only permissions).
    #[serde(rename = "client_credentials")]
    ClientCredentials {
        client_id: String,
        client_secret: String,
        tenant_id: String,
    },

    /// FCP credential reference (resolved by egress proxy).
    #[serde(rename = "credential_id")]
    CredentialId { credential_id: String },
}

fn default_graph_url() -> String {
    "https://graph.microsoft.com/v1.0".into()
}

fn default_bot_url() -> String {
    "https://smba.trafficmanager.net".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph API: Teams & Channels
// ─────────────────────────────────────────────────────────────────────────────

/// Microsoft Teams team.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

/// Microsoft Teams channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub membership_type: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

/// Teams chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub message_type: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub body: Option<MessageBody>,
    #[serde(default)]
    pub from: Option<ChatMessageFrom>,
    #[serde(default)]
    pub importance: Option<String>,
    #[serde(default)]
    pub attachments: Vec<ChatAttachment>,
    #[serde(default)]
    pub web_url: Option<String>,
}

/// Message body content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageBody {
    pub content_type: String,
    pub content: String,
}

/// Message sender info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageFrom {
    #[serde(default)]
    pub user: Option<IdentitySet>,
    #[serde(default)]
    pub application: Option<IdentitySet>,
}

/// Identity info (user or application).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySet {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub user_identity_type: Option<String>,
}

/// Chat message attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatAttachment {
    pub id: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_url: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Teams 1:1 or group chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chat {
    pub id: String,
    #[serde(default)]
    pub topic: Option<String>,
    pub chat_type: String,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

/// Chat member.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMember {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph API: Paging
// ─────────────────────────────────────────────────────────────────────────────

/// Graph API collection response with `OData` paging.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphCollection<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.count")]
    pub count: Option<i64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph API: Error
// ─────────────────────────────────────────────────────────────────────────────

/// Microsoft Graph API error envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphErrorResponse {
    pub error: GraphErrorDetail,
}

/// Graph API error detail.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub inner_error: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Bot Framework: Activity types
// ─────────────────────────────────────────────────────────────────────────────

/// Bot Framework Activity (incoming webhook payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub r#type: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub service_url: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub from: Option<ActivityAccount>,
    #[serde(default)]
    pub conversation: Option<ConversationAccount>,
    #[serde(default)]
    pub recipient: Option<ActivityAccount>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub text_format: Option<String>,
    #[serde(default)]
    pub attachments: Vec<ActivityAttachment>,
    #[serde(default)]
    pub entities: Vec<serde_json::Value>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// Bot Framework account reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityAccount {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub aad_object_id: Option<String>,
}

/// Bot Framework conversation reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationAccount {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub conversation_type: Option<String>,
    #[serde(default)]
    pub is_group: Option<bool>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Bot Framework attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityAttachment {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_url: Option<String>,
    #[serde(default)]
    pub content: Option<serde_json::Value>,
    #[serde(default)]
    pub name: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// OAuth token response
// ─────────────────────────────────────────────────────────────────────────────

/// Azure AD token response.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default)]
    pub scope: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_teams_config_access_token() {
        let json = serde_json::json!({
            "auth": { "mode": "access_token", "access_token": "tok_123" }
        });
        let config: TeamsConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(config.auth, TeamsAuth::AccessToken { .. }));
        assert_eq!(config.graph_base_url, "https://graph.microsoft.com/v1.0");
    }

    #[test]
    fn deserialize_teams_config_client_credentials() {
        let json = serde_json::json!({
            "auth": {
                "mode": "client_credentials",
                "client_id": "app_id",
                "client_secret": "secret",
                "tenant_id": "tenant_abc"
            }
        });
        let config: TeamsConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(config.auth, TeamsAuth::ClientCredentials { .. }));
    }

    #[test]
    fn deserialize_teams_config_credential_id() {
        let json = serde_json::json!({
            "auth": { "mode": "credential_id", "credential_id": "cred_xyz" }
        });
        let config: TeamsConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(config.auth, TeamsAuth::CredentialId { .. }));
    }

    #[test]
    fn deserialize_teams_config_with_overrides() {
        let json = serde_json::json!({
            "auth": { "mode": "access_token", "access_token": "tok" },
            "graph_base_url": "https://custom.graph.com",
            "tenant_id": "my_tenant",
            "timeout_ms": 60000
        });
        let config: TeamsConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.graph_base_url, "https://custom.graph.com");
        assert_eq!(config.tenant_id, Some("my_tenant".into()));
        assert_eq!(config.timeout_ms, 60000);
    }

    #[test]
    fn deserialize_team() {
        let json = serde_json::json!({
            "id": "team_1",
            "displayName": "Engineering",
            "description": "Eng team",
            "visibility": "private"
        });
        let team: Team = serde_json::from_value(json).unwrap();
        assert_eq!(team.id, "team_1");
        assert_eq!(team.display_name, "Engineering");
        assert_eq!(team.visibility, Some("private".into()));
    }

    #[test]
    fn deserialize_channel() {
        let json = serde_json::json!({
            "id": "ch_1",
            "displayName": "General",
            "membershipType": "standard"
        });
        let channel: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(channel.id, "ch_1");
        assert_eq!(channel.membership_type, Some("standard".into()));
    }

    #[test]
    fn deserialize_chat_message() {
        let json = serde_json::json!({
            "id": "msg_1",
            "messageType": "message",
            "createdDateTime": "2026-01-01T00:00:00Z",
            "body": {
                "contentType": "text",
                "content": "Hello Teams!"
            },
            "from": {
                "user": {
                    "id": "user_1",
                    "displayName": "Alice"
                }
            },
            "importance": "normal",
            "attachments": []
        });
        let msg: ChatMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.id, Some("msg_1".into()));
        assert_eq!(msg.body.as_ref().unwrap().content, "Hello Teams!");
        assert_eq!(
            msg.from
                .as_ref()
                .unwrap()
                .user
                .as_ref()
                .unwrap()
                .display_name,
            Some("Alice".into())
        );
    }

    #[test]
    fn deserialize_chat_message_minimal() {
        let json = serde_json::json!({
            "body": { "contentType": "html", "content": "<p>Hi</p>" }
        });
        let msg: ChatMessage = serde_json::from_value(json).unwrap();
        assert!(msg.id.is_none());
        assert_eq!(msg.body.unwrap().content_type, "html");
    }

    #[test]
    fn deserialize_chat() {
        let json = serde_json::json!({
            "id": "chat_1",
            "chatType": "oneOnOne",
            "createdDateTime": "2026-01-01T00:00:00Z"
        });
        let chat: Chat = serde_json::from_value(json).unwrap();
        assert_eq!(chat.chat_type, "oneOnOne");
    }

    #[test]
    fn deserialize_graph_collection() {
        let json = serde_json::json!({
            "value": [
                { "id": "ch_1", "displayName": "General" },
                { "id": "ch_2", "displayName": "Random" }
            ],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/teams/t1/channels?$skip=2",
            "@odata.count": 5
        });
        let coll: GraphCollection<Channel> = serde_json::from_value(json).unwrap();
        assert_eq!(coll.value.len(), 2);
        assert!(coll.next_link.is_some());
        assert_eq!(coll.count, Some(5));
    }

    #[test]
    fn deserialize_graph_collection_no_paging() {
        let json = serde_json::json!({
            "value": [{ "id": "t1", "displayName": "Team A" }]
        });
        let coll: GraphCollection<Team> = serde_json::from_value(json).unwrap();
        assert_eq!(coll.value.len(), 1);
        assert!(coll.next_link.is_none());
    }

    #[test]
    fn deserialize_graph_error() {
        let json = serde_json::json!({
            "error": {
                "code": "Forbidden",
                "message": "Insufficient privileges to complete the operation."
            }
        });
        let err: GraphErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.code, "Forbidden");
    }

    #[test]
    fn deserialize_activity() {
        let json = serde_json::json!({
            "type": "message",
            "id": "act_1",
            "timestamp": "2026-01-01T00:00:00Z",
            "serviceUrl": "https://smba.trafficmanager.net/amer/",
            "channelId": "msteams",
            "from": { "id": "user:123", "name": "Alice" },
            "conversation": {
                "id": "conv:1",
                "conversationType": "personal",
                "tenantId": "tenant_1"
            },
            "text": "Hello bot!",
            "attachments": [],
            "entities": []
        });
        let activity: Activity = serde_json::from_value(json).unwrap();
        assert_eq!(activity.r#type, "message");
        assert_eq!(activity.text, Some("Hello bot!".into()));
        assert_eq!(
            activity.conversation.as_ref().unwrap().tenant_id,
            Some("tenant_1".into())
        );
    }

    #[test]
    fn deserialize_activity_minimal() {
        let json = serde_json::json!({ "type": "conversationUpdate" });
        let activity: Activity = serde_json::from_value(json).unwrap();
        assert_eq!(activity.r#type, "conversationUpdate");
        assert!(activity.text.is_none());
    }

    #[test]
    fn deserialize_token_response() {
        let json = serde_json::json!({
            "access_token": "eyJ0...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://graph.microsoft.com/.default"
        });
        let token: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
    }

    #[test]
    fn serialize_message_body() {
        let body = MessageBody {
            content_type: "text".into(),
            content: "Hello".into(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["contentType"], "text");
        assert_eq!(json["content"], "Hello");
    }

    #[test]
    fn team_serialization_roundtrip() {
        let team = Team {
            id: "t1".into(),
            display_name: "Test Team".into(),
            description: Some("A test".into()),
            visibility: Some("public".into()),
            web_url: None,
        };
        let json = serde_json::to_value(&team).unwrap();
        let deserialized: Team = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.id, "t1");
        assert_eq!(deserialized.display_name, "Test Team");
    }

    #[test]
    fn chat_member_deserialization() {
        let json = serde_json::json!({
            "id": "mem_1",
            "displayName": "Bob",
            "roles": ["owner"],
            "userId": "user_bob",
            "email": "bob@contoso.com"
        });
        let member: ChatMember = serde_json::from_value(json).unwrap();
        assert_eq!(member.roles, vec!["owner"]);
        assert_eq!(member.email, Some("bob@contoso.com".into()));
    }

    #[test]
    fn chat_attachment_deserialization() {
        let json = serde_json::json!({
            "id": "att_1",
            "contentType": "reference",
            "contentUrl": "https://example.com/file.pdf",
            "name": "report.pdf"
        });
        let att: ChatAttachment = serde_json::from_value(json).unwrap();
        assert_eq!(att.name, Some("report.pdf".into()));
    }

    #[test]
    fn default_config_urls() {
        assert_eq!(
            default_graph_url(),
            "https://graph.microsoft.com/v1.0"
        );
        assert_eq!(
            default_bot_url(),
            "https://smba.trafficmanager.net"
        );
        assert_eq!(default_timeout_ms(), 30_000);
    }
}
