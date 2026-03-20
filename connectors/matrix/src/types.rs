//! Matrix protocol types.
//!
//! Covers Client-Server API: rooms, events, sync, and media.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Matrix connector configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MatrixConfig {
    /// Homeserver URL (e.g., `https://matrix.org`).
    pub homeserver_url: String,

    /// Authentication mode.
    pub auth: MatrixAuth,

    /// HTTP retry configuration.
    #[serde(default)]
    pub retry: fcp_sdk::migration::HttpRetryConfig,

    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Authentication mode for Matrix.
#[derive(Clone, Deserialize)]
#[serde(tag = "mode")]
pub enum MatrixAuth {
    /// Direct access token.
    #[serde(rename = "access_token")]
    AccessToken { access_token: String },

    /// FCP credential reference (resolved by egress proxy).
    #[serde(rename = "credential_id")]
    CredentialId { credential_id: String },
}

impl std::fmt::Debug for MatrixAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId { credential_id } => f
                .debug_struct("CredentialId")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

const fn default_timeout_ms() -> u64 {
    30_000
}

// ─────────────────────────────────────────────────────────────────────────────
// Rooms
// ─────────────────────────────────────────────────────────────────────────────

/// Matrix room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub room_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub canonical_alias: Option<String>,
    #[serde(default)]
    pub num_joined_members: Option<u64>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

/// Room creation request.
#[derive(Debug, Clone, Serialize)]
pub struct CreateRoomRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_alias_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invite: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
}

/// Room creation response.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateRoomResponse {
    pub room_id: String,
}

/// Joined rooms response.
#[derive(Debug, Clone, Deserialize)]
pub struct JoinedRoomsResponse {
    pub joined_rooms: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Events / Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Matrix event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub event_id: Option<String>,
    pub r#type: String,
    #[serde(default)]
    pub state_key: Option<String>,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub origin_server_ts: Option<u64>,
    #[serde(default)]
    pub content: serde_json::Value,
    #[serde(default)]
    pub room_id: Option<String>,
}

/// Message event content (`m.room.message`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContent {
    pub msgtype: String,
    pub body: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub formatted_body: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// Event send response.
#[derive(Debug, Clone, Deserialize)]
pub struct SendEventResponse {
    pub event_id: String,
}

/// Messages response (paginated).
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    #[serde(default)]
    pub chunk: Vec<Event>,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub end: Option<String>,
}

/// Members response for a room.
#[derive(Debug, Clone, Deserialize)]
pub struct MembersResponse {
    #[serde(default)]
    pub chunk: Vec<Event>,
}

/// Media upload response.
#[derive(Debug, Clone, Deserialize)]
pub struct MediaUploadResponse {
    pub content_uri: String,
}

/// Downloaded media payload and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedMedia {
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sync
// ─────────────────────────────────────────────────────────────────────────────

/// Sync response (simplified).
#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    pub next_batch: String,
    #[serde(default)]
    pub rooms: SyncRooms,
}

/// Sync rooms section.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SyncRooms {
    #[serde(default)]
    pub join: std::collections::BTreeMap<String, JoinedSyncRoom>,
    #[serde(default)]
    pub invite: std::collections::BTreeMap<String, InvitedSyncRoom>,
    #[serde(default)]
    pub leave: std::collections::BTreeMap<String, LeftSyncRoom>,
}

/// Generic event list used by sync sections.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SyncEventList {
    #[serde(default)]
    pub events: Vec<Event>,
}

/// Timeline section for joined and left rooms.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SyncTimeline {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub prev_batch: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

/// Joined room data returned by `/sync`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct JoinedSyncRoom {
    #[serde(default)]
    pub state: SyncEventList,
    #[serde(default)]
    pub timeline: SyncTimeline,
}

/// Invite-only room data returned by `/sync`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct InvitedSyncRoom {
    #[serde(default)]
    pub invite_state: SyncEventList,
}

/// Left room data returned by `/sync`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LeftSyncRoom {
    #[serde(default)]
    pub state: SyncEventList,
    #[serde(default)]
    pub timeline: SyncTimeline,
}

// ─────────────────────────────────────────────────────────────────────────────
// User
// ─────────────────────────────────────────────────────────────────────────────

/// User info (`whoami` response).
#[derive(Debug, Clone, Deserialize)]
pub struct WhoAmIResponse {
    pub user_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Matrix API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct MatrixErrorResponse {
    pub errcode: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_config_access_token() {
        let json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "syt_abc" }
        });
        let config: MatrixConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.homeserver_url, "https://matrix.org");
        assert!(matches!(config.auth, MatrixAuth::AccessToken { .. }));
    }

    #[test]
    fn deserialize_config_credential_id() {
        let json = serde_json::json!({
            "homeserver_url": "https://my.server",
            "auth": { "mode": "credential_id", "credential_id": "cred_1" }
        });
        let config: MatrixConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(config.auth, MatrixAuth::CredentialId { .. }));
    }

    #[test]
    fn deserialize_config_with_timeout() {
        let json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "timeout_ms": 60000
        });
        let config: MatrixConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.timeout_ms, 60000);
    }

    #[test]
    fn deserialize_room() {
        let json = serde_json::json!({
            "room_id": "!abc:matrix.org",
            "name": "General",
            "topic": "Main room",
            "num_joined_members": 42
        });
        let room: Room = serde_json::from_value(json).unwrap();
        assert_eq!(room.room_id, "!abc:matrix.org");
        assert_eq!(room.num_joined_members, Some(42));
    }

    #[test]
    fn deserialize_event() {
        let json = serde_json::json!({
            "event_id": "$ev1",
            "type": "m.room.message",
            "sender": "@alice:matrix.org",
            "origin_server_ts": 1_677_000_000_000_u64,
            "content": { "msgtype": "m.text", "body": "Hello" },
            "room_id": "!room:matrix.org"
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.r#type, "m.room.message");
        assert_eq!(event.sender, Some("@alice:matrix.org".into()));
        assert_eq!(event.state_key, None);
    }

    #[test]
    fn deserialize_message_content() {
        let json = serde_json::json!({
            "msgtype": "m.text",
            "body": "Hello Matrix!",
            "format": "org.matrix.custom.html",
            "formatted_body": "<b>Hello</b>"
        });
        let content: MessageContent = serde_json::from_value(json).unwrap();
        assert_eq!(content.msgtype, "m.text");
        assert_eq!(content.formatted_body, Some("<b>Hello</b>".into()));
    }

    #[test]
    fn deserialize_send_event_response() {
        let json = serde_json::json!({ "event_id": "$new_event" });
        let resp: SendEventResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.event_id, "$new_event");
    }

    #[test]
    fn deserialize_messages_response() {
        let json = serde_json::json!({
            "chunk": [
                { "event_id": "$1", "type": "m.room.message", "content": {} }
            ],
            "start": "s1",
            "end": "s2"
        });
        let resp: MessagesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.chunk.len(), 1);
        assert_eq!(resp.start, Some("s1".into()));
    }

    #[test]
    fn deserialize_sync_response() {
        let json = serde_json::json!({
            "next_batch": "batch_token_123"
        });
        let resp: SyncResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_batch, "batch_token_123");
        assert!(resp.rooms.join.is_empty());
    }

    #[test]
    fn deserialize_sync_response_with_room_sections() {
        let json = serde_json::json!({
            "next_batch": "batch_token_123",
            "rooms": {
                "join": {
                    "!room:matrix.org": {
                        "state": {
                            "events": [
                                {
                                    "type": "m.room.name",
                                    "state_key": "",
                                    "content": { "name": "General" }
                                }
                            ]
                        },
                        "timeline": {
                            "events": [
                                {
                                    "event_id": "$1",
                                    "type": "m.room.message",
                                    "sender": "@alice:matrix.org",
                                    "content": { "msgtype": "m.text", "body": "Hello" }
                                }
                            ],
                            "prev_batch": "prev",
                            "limited": false
                        }
                    }
                }
            }
        });

        let resp: SyncResponse = serde_json::from_value(json).unwrap();
        let joined = resp.rooms.join.get("!room:matrix.org").unwrap();
        assert_eq!(joined.state.events.len(), 1);
        assert_eq!(joined.timeline.events.len(), 1);
        assert_eq!(joined.timeline.prev_batch.as_deref(), Some("prev"));
    }

    #[test]
    fn deserialize_whoami() {
        let json = serde_json::json!({
            "user_id": "@bot:matrix.org",
            "device_id": "ABCDEF"
        });
        let resp: WhoAmIResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.user_id, "@bot:matrix.org");
    }

    #[test]
    fn deserialize_error_response() {
        let json = serde_json::json!({
            "errcode": "M_FORBIDDEN",
            "error": "You are not invited to this room."
        });
        let err: MatrixErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.errcode, "M_FORBIDDEN");
    }

    #[test]
    fn deserialize_joined_rooms() {
        let json = serde_json::json!({
            "joined_rooms": ["!a:m.org", "!b:m.org"]
        });
        let resp: JoinedRoomsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.joined_rooms.len(), 2);
    }

    #[test]
    fn deserialize_members_response() {
        let json = serde_json::json!({
            "chunk": [
                {
                    "type": "m.room.member",
                    "state_key": "@alice:matrix.org",
                    "content": {
                        "membership": "join",
                        "displayname": "Alice"
                    }
                }
            ]
        });
        let resp: MembersResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.chunk.len(), 1);
        assert_eq!(
            resp.chunk[0].state_key.as_deref(),
            Some("@alice:matrix.org")
        );
    }

    #[test]
    fn deserialize_media_upload_response() {
        let json = serde_json::json!({
            "content_uri": "mxc://matrix.org/abc123"
        });
        let resp: MediaUploadResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.content_uri, "mxc://matrix.org/abc123");
    }

    #[test]
    fn create_room_serialization() {
        let req = CreateRoomRequest {
            name: Some("Test Room".into()),
            topic: None,
            room_alias_name: None,
            invite: vec!["@user:matrix.org".into()],
            visibility: Some("private".into()),
            preset: Some("private_chat".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "Test Room");
        assert_eq!(json["invite"][0], "@user:matrix.org");
        assert!(json.get("topic").is_none());
    }

    #[test]
    fn default_timeout() {
        assert_eq!(default_timeout_ms(), 30_000);
    }
}
