//! Google Chat API v1 data types.

use serde::{Deserialize, Serialize};

/// A Google Chat space (room, DM, or group chat).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Space {
    /// Resource name of the space (e.g. `spaces/AAAA`).
    pub name: String,
    /// Display name of the space.
    #[serde(default)]
    pub display_name: String,
    /// Type of the space.
    #[serde(default, rename = "spaceType")]
    pub space_type: SpaceType,
    /// Whether the space uses threaded replies.
    #[serde(default)]
    pub threaded: bool,
}

/// Type of a Google Chat space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpaceType {
    /// A named space (room).
    #[default]
    Room,
    /// A direct message between two users.
    DirectMessage,
    /// A group chat (unnamed, multiple users).
    GroupChat,
}

/// A message in a Google Chat space.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// Resource name of the message.
    #[serde(default)]
    pub name: String,
    /// The user who sent the message.
    #[serde(default)]
    pub sender: Option<User>,
    /// Plain-text body of the message.
    #[serde(default)]
    pub text: String,
    /// Timestamp when the message was created (RFC 3339).
    #[serde(default)]
    pub create_time: String,
    /// Thread the message belongs to.
    #[serde(default)]
    pub thread: Option<Thread>,
}

/// A thread in a Google Chat space.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thread {
    /// Resource name of the thread.
    #[serde(default)]
    pub name: String,
    /// Opaque thread key set by the creator.
    #[serde(default)]
    pub thread_key: String,
}

/// A Google Chat user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// Resource name of the user.
    pub name: String,
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Domain ID of the user's organization.
    #[serde(default)]
    pub domain_id: String,
    /// Type of user (HUMAN or BOT).
    #[serde(default, rename = "type")]
    pub type_field: String,
}

/// A membership in a Google Chat space.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    /// Resource name of the membership.
    pub name: String,
    /// The member (user).
    #[serde(default)]
    pub member: Option<User>,
    /// State of the membership.
    #[serde(default)]
    pub state: MembershipState,
    /// Role of the member in the space.
    #[serde(default)]
    pub role: MembershipRole,
    /// Timestamp when the membership was created (RFC 3339).
    #[serde(default)]
    pub create_time: String,
}

/// State of a membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MembershipState {
    /// The user has joined the space.
    #[default]
    Joined,
    /// The user has been invited to the space.
    Invited,
    /// The user is not a member.
    NotAMember,
}

/// Role of a member in a space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MembershipRole {
    /// Regular member.
    #[default]
    Member,
    /// Space manager.
    Manager,
}

/// Response from listing spaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSpacesResponse {
    #[serde(default)]
    pub spaces: Vec<Space>,
    #[serde(default)]
    pub next_page_token: String,
}

/// Response from listing messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesResponse {
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub next_page_token: String,
}

/// Response from listing memberships.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMembershipsResponse {
    #[serde(default)]
    pub memberships: Vec<Membership>,
    #[serde(default)]
    pub next_page_token: String,
}

/// Google Chat API error response.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub error: ApiErrorDetail,
}

/// Error detail from the API.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorDetail {
    pub code: u16,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_serde() {
        let json = r#"{
            "name": "spaces/AAAA",
            "displayName": "General",
            "spaceType": "ROOM",
            "threaded": true
        }"#;
        let space: Space = serde_json::from_str(json).unwrap();
        assert_eq!(space.name, "spaces/AAAA");
        assert_eq!(space.display_name, "General");
        assert_eq!(space.space_type, SpaceType::Room);
        assert!(space.threaded);
    }

    #[test]
    fn space_direct_message() {
        let json = r#"{
            "name": "spaces/BBBB",
            "displayName": "",
            "spaceType": "DIRECT_MESSAGE",
            "threaded": false
        }"#;
        let space: Space = serde_json::from_str(json).unwrap();
        assert_eq!(space.space_type, SpaceType::DirectMessage);
        assert!(!space.threaded);
    }

    #[test]
    fn space_group_chat() {
        let json = r#"{
            "name": "spaces/CCCC",
            "spaceType": "GROUP_CHAT"
        }"#;
        let space: Space = serde_json::from_str(json).unwrap();
        assert_eq!(space.space_type, SpaceType::GroupChat);
    }

    #[test]
    fn space_default_type() {
        let json = r#"{"name": "spaces/DDDD"}"#;
        let space: Space = serde_json::from_str(json).unwrap();
        assert_eq!(space.space_type, SpaceType::Room);
    }

    #[test]
    fn message_serde() {
        let json = r#"{
            "name": "spaces/AAAA/messages/msg1",
            "sender": {
                "name": "users/123",
                "displayName": "Alice",
                "domainId": "domain1",
                "type": "HUMAN"
            },
            "text": "Hello, world!",
            "createTime": "2026-03-14T10:00:00Z",
            "thread": {
                "name": "spaces/AAAA/threads/thread1",
                "threadKey": "my-thread-key"
            }
        }"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.name, "spaces/AAAA/messages/msg1");
        assert_eq!(msg.text, "Hello, world!");
        let sender = msg.sender.unwrap();
        assert_eq!(sender.display_name, "Alice");
        assert_eq!(sender.type_field, "HUMAN");
        let thread = msg.thread.unwrap();
        assert_eq!(thread.thread_key, "my-thread-key");
    }

    #[test]
    fn message_minimal() {
        let json = r#"{"text": "Hi"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.text, "Hi");
        assert!(msg.name.is_empty());
        assert!(msg.sender.is_none());
        assert!(msg.thread.is_none());
    }

    #[test]
    fn thread_serde() {
        let json = r#"{
            "name": "spaces/AAAA/threads/t1",
            "threadKey": "key1"
        }"#;
        let thread: Thread = serde_json::from_str(json).unwrap();
        assert_eq!(thread.name, "spaces/AAAA/threads/t1");
        assert_eq!(thread.thread_key, "key1");
    }

    #[test]
    fn user_serde() {
        let json = r#"{
            "name": "users/456",
            "displayName": "Bob",
            "domainId": "d1",
            "type": "BOT"
        }"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.name, "users/456");
        assert_eq!(user.display_name, "Bob");
        assert_eq!(user.type_field, "BOT");
    }

    #[test]
    fn membership_serde() {
        let json = r#"{
            "name": "spaces/AAAA/members/123",
            "member": {
                "name": "users/123",
                "displayName": "Alice",
                "domainId": "d1",
                "type": "HUMAN"
            },
            "state": "JOINED",
            "role": "MANAGER",
            "createTime": "2026-01-01T00:00:00Z"
        }"#;
        let m: Membership = serde_json::from_str(json).unwrap();
        assert_eq!(m.name, "spaces/AAAA/members/123");
        assert_eq!(m.state, MembershipState::Joined);
        assert_eq!(m.role, MembershipRole::Manager);
        let member = m.member.unwrap();
        assert_eq!(member.display_name, "Alice");
    }

    #[test]
    fn membership_invited() {
        let json = r#"{
            "name": "spaces/AAAA/members/456",
            "state": "INVITED",
            "role": "MEMBER"
        }"#;
        let m: Membership = serde_json::from_str(json).unwrap();
        assert_eq!(m.state, MembershipState::Invited);
        assert_eq!(m.role, MembershipRole::Member);
    }

    #[test]
    fn membership_not_a_member() {
        let json = r#"{
            "name": "spaces/AAAA/members/789",
            "state": "NOT_A_MEMBER"
        }"#;
        let m: Membership = serde_json::from_str(json).unwrap();
        assert_eq!(m.state, MembershipState::NotAMember);
    }

    #[test]
    fn membership_default_state_and_role() {
        let json = r#"{"name": "spaces/AAAA/members/000"}"#;
        let m: Membership = serde_json::from_str(json).unwrap();
        assert_eq!(m.state, MembershipState::Joined);
        assert_eq!(m.role, MembershipRole::Member);
    }

    #[test]
    fn list_spaces_response_serde() {
        let json = r#"{
            "spaces": [
                {"name": "spaces/AAAA", "displayName": "General"},
                {"name": "spaces/BBBB", "displayName": "Random"}
            ],
            "nextPageToken": "token123"
        }"#;
        let resp: ListSpacesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.spaces.len(), 2);
        assert_eq!(resp.next_page_token, "token123");
    }

    #[test]
    fn list_spaces_response_empty() {
        let json = r"{}";
        let resp: ListSpacesResponse = serde_json::from_str(json).unwrap();
        assert!(resp.spaces.is_empty());
        assert!(resp.next_page_token.is_empty());
    }

    #[test]
    fn list_messages_response_serde() {
        let json = r#"{
            "messages": [
                {"name": "spaces/AAAA/messages/m1", "text": "Hello"}
            ],
            "nextPageToken": ""
        }"#;
        let resp: ListMessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.messages.len(), 1);
        assert_eq!(resp.messages[0].text, "Hello");
    }

    #[test]
    fn list_memberships_response_serde() {
        let json = r#"{
            "memberships": [
                {"name": "spaces/AAAA/members/1", "state": "JOINED", "role": "MEMBER"}
            ]
        }"#;
        let resp: ListMembershipsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.memberships.len(), 1);
    }

    #[test]
    fn api_error_response_serde() {
        let json = r#"{"error": {"code": 404, "message": "not found"}}"#;
        let er: ApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(er.error.code, 404);
    }

    #[test]
    fn space_roundtrip() {
        let space = Space {
            name: "spaces/AAAA".into(),
            display_name: "Test".into(),
            space_type: SpaceType::Room,
            threaded: true,
        };
        let json = serde_json::to_string(&space).unwrap();
        let deserialized: Space = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, space.name);
        assert_eq!(deserialized.display_name, space.display_name);
        assert_eq!(deserialized.space_type, space.space_type);
        assert_eq!(deserialized.threaded, space.threaded);
    }

    #[test]
    fn message_roundtrip() {
        let msg = Message {
            name: "spaces/AAAA/messages/m1".into(),
            sender: Some(User {
                name: "users/1".into(),
                display_name: "Test".into(),
                domain_id: "d1".into(),
                type_field: "HUMAN".into(),
            }),
            text: "test message".into(),
            create_time: "2026-03-14T00:00:00Z".into(),
            thread: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.text, "test message");
    }

    #[test]
    fn space_type_debug() {
        let dbg = format!("{:?}", SpaceType::DirectMessage);
        assert!(dbg.contains("DirectMessage"));
    }

    #[test]
    fn membership_state_debug() {
        let dbg = format!("{:?}", MembershipState::NotAMember);
        assert!(dbg.contains("NotAMember"));
    }

    #[test]
    fn membership_role_debug() {
        let dbg = format!("{:?}", MembershipRole::Manager);
        assert!(dbg.contains("Manager"));
    }
}
