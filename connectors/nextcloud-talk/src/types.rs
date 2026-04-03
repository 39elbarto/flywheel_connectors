//! Nextcloud Talk request, response, and state model types.

#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// OCS JSON envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsEnvelope<T> {
    pub ocs: OcsBody<T>,
}

/// OCS response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsBody<T> {
    pub meta: OcsMeta,
    pub data: T,
}

/// OCS response metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsMeta {
    pub status: String,
    pub statuscode: i64,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub totalitems: Option<String>,
    #[serde(default)]
    pub itemsperpage: Option<String>,
}

/// Strongly-typed conversation token.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConversationToken(pub String);

impl ConversationToken {
    /// Create a validated conversation token.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("conversation token must not be empty".into());
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Borrow the raw conversation token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strongly-typed message identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(pub u64);

impl MessageId {
    /// Borrow the raw message identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Strongly-typed attendee identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttendeeId(pub u64);

impl AttendeeId {
    /// Borrow the raw attendee identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Strongly-typed chat reference identifier used for idempotent correlation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReferenceId(pub String);

impl ReferenceId {
    /// Create a validated reference identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("reference_id must not be empty".into());
        }
        Ok(Self(trimmed.to_string()))
    }
}

fn validate_optional_non_empty(field: &str, value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value
        && value.trim().is_empty()
    {
        return Err(format!("{field} must not be empty when provided"));
    }
    Ok(())
}

/// Conversation type constants from the Talk API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub enum ConversationType {
    OneToOne,
    Group,
    Public,
    ChangeLog,
    FormerOneToOne,
    NoteToSelf,
    Unknown(u8),
}

impl From<u8> for ConversationType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::OneToOne,
            2 => Self::Group,
            3 => Self::Public,
            4 => Self::ChangeLog,
            5 => Self::FormerOneToOne,
            6 => Self::NoteToSelf,
            other => Self::Unknown(other),
        }
    }
}

impl From<ConversationType> for u8 {
    fn from(value: ConversationType) -> Self {
        match value {
            ConversationType::OneToOne => 1,
            ConversationType::Group => 2,
            ConversationType::Public => 3,
            ConversationType::ChangeLog => 4,
            ConversationType::FormerOneToOne => 5,
            ConversationType::NoteToSelf => 6,
            ConversationType::Unknown(other) => other,
        }
    }
}

/// Participant permission level in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub enum ParticipantType {
    Owner,
    Moderator,
    User,
    Guest,
    SelfJoinedUser,
    GuestModerator,
    Unknown(u8),
}

impl From<u8> for ParticipantType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Owner,
            2 => Self::Moderator,
            3 => Self::User,
            4 => Self::Guest,
            5 => Self::SelfJoinedUser,
            6 => Self::GuestModerator,
            other => Self::Unknown(other),
        }
    }
}

impl From<ParticipantType> for u8 {
    fn from(value: ParticipantType) -> Self {
        match value {
            ParticipantType::Owner => 1,
            ParticipantType::Moderator => 2,
            ParticipantType::User => 3,
            ParticipantType::Guest => 4,
            ParticipantType::SelfJoinedUser => 5,
            ParticipantType::GuestModerator => 6,
            ParticipantType::Unknown(other) => other,
        }
    }
}

/// Session-state constants used when suppressing notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub enum SessionState {
    Inactive,
    Active,
    Unknown(u8),
}

impl From<u8> for SessionState {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Inactive,
            1 => Self::Active,
            other => Self::Unknown(other),
        }
    }
}

impl From<SessionState> for u8 {
    fn from(value: SessionState) -> Self {
        match value {
            SessionState::Inactive => 0,
            SessionState::Active => 1,
            SessionState::Unknown(other) => other,
        }
    }
}

/// Actor type used for participants and call attendees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum AttendeeActorType {
    Users,
    FederatedUsers,
    Groups,
    Circles,
    Guests,
    Emails,
    Unknown(String),
}

impl From<String> for AttendeeActorType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "users" => Self::Users,
            "federated_users" => Self::FederatedUsers,
            "groups" => Self::Groups,
            "circles" => Self::Circles,
            "guests" => Self::Guests,
            "emails" => Self::Emails,
            _ => Self::Unknown(value),
        }
    }
}

impl From<AttendeeActorType> for String {
    fn from(value: AttendeeActorType) -> Self {
        match value {
            AttendeeActorType::Users => "users".into(),
            AttendeeActorType::FederatedUsers => "federated_users".into(),
            AttendeeActorType::Groups => "groups".into(),
            AttendeeActorType::Circles => "circles".into(),
            AttendeeActorType::Guests => "guests".into(),
            AttendeeActorType::Emails => "emails".into(),
            AttendeeActorType::Unknown(other) => other,
        }
    }
}

/// Actor type used by chat messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ChatActorType {
    Users,
    Guests,
    Bots,
    Bridged,
    DeletedUsers,
    FederatedUsers,
    Unknown(String),
}

impl From<String> for ChatActorType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "users" => Self::Users,
            "guests" => Self::Guests,
            "bots" => Self::Bots,
            "bridged" => Self::Bridged,
            "deleted_users" => Self::DeletedUsers,
            "federated_users" => Self::FederatedUsers,
            _ => Self::Unknown(value),
        }
    }
}

impl From<ChatActorType> for String {
    fn from(value: ChatActorType) -> Self {
        match value {
            ChatActorType::Users => "users".into(),
            ChatActorType::Guests => "guests".into(),
            ChatActorType::Bots => "bots".into(),
            ChatActorType::Bridged => "bridged".into(),
            ChatActorType::DeletedUsers => "deleted_users".into(),
            ChatActorType::FederatedUsers => "federated_users".into(),
            ChatActorType::Unknown(other) => other,
        }
    }
}

/// Shared item classifications surfaced by the Talk API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum SharedItemType {
    Audio,
    DeckCard,
    File,
    Location,
    Media,
    Other,
    Voice,
    Recording,
    Unknown(String),
}

impl From<String> for SharedItemType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "audio" => Self::Audio,
            "deckcard" => Self::DeckCard,
            "file" => Self::File,
            "location" => Self::Location,
            "media" => Self::Media,
            "other" => Self::Other,
            "voice" => Self::Voice,
            "recording" => Self::Recording,
            _ => Self::Unknown(value),
        }
    }
}

impl From<SharedItemType> for String {
    fn from(value: SharedItemType) -> Self {
        match value {
            SharedItemType::Audio => "audio".into(),
            SharedItemType::DeckCard => "deckcard".into(),
            SharedItemType::File => "file".into(),
            SharedItemType::Location => "location".into(),
            SharedItemType::Media => "media".into(),
            SharedItemType::Other => "other".into(),
            SharedItemType::Voice => "voice".into(),
            SharedItemType::Recording => "recording".into(),
            SharedItemType::Unknown(other) => other,
        }
    }
}

/// Response body from the standard Nextcloud capabilities endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilitiesResponse {
    pub version: NextcloudVersionInfo,
    #[serde(default)]
    pub capabilities: ServerCapabilities,
}

/// Basic Nextcloud server version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextcloudVersionInfo {
    #[serde(default)]
    pub major: Option<u64>,
    #[serde(default)]
    pub minor: Option<u64>,
    #[serde(default)]
    pub micro: Option<u64>,
    #[serde(default)]
    pub string: Option<String>,
    #[serde(default)]
    pub edition: Option<String>,
}

/// Capability groups returned by the Nextcloud server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(default)]
    pub spreed: Option<TalkCapabilities>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Nextcloud Talk-specific capability block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TalkCapabilities {
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Query parameters for listing conversations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationListQuery {
    #[serde(default)]
    pub include_status: bool,
    #[serde(default)]
    pub modified_since: Option<i64>,
}

/// Query parameters for chat history and long-polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChatMessagesQuery {
    #[serde(default)]
    pub look_into_future: bool,
    #[serde(default)]
    pub limit: Option<u16>,
    #[serde(default)]
    pub last_known_message_id: Option<MessageId>,
    #[serde(default)]
    pub last_common_read_id: Option<MessageId>,
    #[serde(default)]
    pub timeout_secs: Option<u16>,
    #[serde(default = "default_true")]
    pub set_read_marker: bool,
    #[serde(default)]
    pub include_last_known: bool,
    #[serde(default)]
    pub no_status_update: bool,
    #[serde(default = "default_true")]
    pub mark_notifications_as_read: bool,
}

impl Default for ChatMessagesQuery {
    fn default() -> Self {
        Self {
            look_into_future: false,
            limit: None,
            last_known_message_id: None,
            last_common_read_id: None,
            timeout_secs: None,
            set_read_marker: true,
            include_last_known: false,
            no_status_update: false,
            mark_notifications_as_read: true,
        }
    }
}

impl ChatMessagesQuery {
    /// Validate documented bounds for chat retrieval.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(limit) = self.limit
            && (limit == 0 || limit > 200)
        {
            return Err("chat limit must be between 1 and 200".into());
        }
        if let Some(timeout_secs) = self.timeout_secs
            && (timeout_secs == 0 || timeout_secs > 60)
        {
            return Err("chat timeout_secs must be between 1 and 60".into());
        }
        Ok(())
    }
}

/// Query parameters for participant listing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParticipantListQuery {
    #[serde(default)]
    pub include_status: bool,
}

/// Request body for creating a conversation.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateConversationRequest {
    pub room_type: ConversationType,
    #[serde(default)]
    pub invite: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub room_name: Option<String>,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub object_id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl std::fmt::Debug for CreateConversationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateConversationRequest")
            .field("room_type", &self.room_type)
            .field("invite", &self.invite)
            .field("source", &self.source)
            .field("room_name", &self.room_name)
            .field("object_type", &self.object_type)
            .field("object_id", &self.object_id)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl CreateConversationRequest {
    /// Validate outbound room-creation inputs before hitting the HTTP API.
    pub fn validate(&self) -> Result<(), String> {
        if matches!(self.room_type, ConversationType::Unknown(_)) {
            return Err(
                "room_type must be one of the documented Nextcloud Talk values (1-6)".into(),
            );
        }
        validate_optional_non_empty("invite", self.invite.as_deref())?;
        validate_optional_non_empty("source", self.source.as_deref())?;
        validate_optional_non_empty("room_name", self.room_name.as_deref())?;
        validate_optional_non_empty("object_type", self.object_type.as_deref())?;
        validate_optional_non_empty("object_id", self.object_id.as_deref())?;
        validate_optional_non_empty("password", self.password.as_deref())?;
        Ok(())
    }
}

/// Request body for sending a chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendChatMessageRequest {
    pub message: String,
    #[serde(default)]
    pub actor_display_name: Option<String>,
    #[serde(default)]
    pub reply_to: Option<MessageId>,
    #[serde(default)]
    pub reference_id: Option<ReferenceId>,
    #[serde(default)]
    pub silent: bool,
}

impl SendChatMessageRequest {
    /// Validate outbound chat message inputs.
    pub fn validate(&self) -> Result<(), String> {
        if self.message.trim().is_empty() {
            return Err("message must not be empty".into());
        }
        validate_optional_non_empty("actor_display_name", self.actor_display_name.as_deref())?;
        if let Some(reference_id) = &self.reference_id
            && reference_id.0.trim().is_empty()
        {
            return Err("reference_id must not be empty when provided".into());
        }
        Ok(())
    }
}

/// Request body for adding or removing reactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionRequest {
    pub reaction: String,
}

impl ReactionRequest {
    /// Validate the reaction payload.
    pub fn validate(&self) -> Result<(), String> {
        if self.reaction.trim().is_empty() {
            return Err("reaction must not be empty".into());
        }
        Ok(())
    }
}

/// Request body for marking chat read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadMarkerRequest {
    #[serde(default)]
    pub last_read_message: Option<MessageId>,
}

/// Request body for adding a participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddParticipantRequest {
    pub new_participant: String,
    #[serde(default)]
    pub source: Option<String>,
}

impl AddParticipantRequest {
    /// Validate an attendee-add request before it reaches the API.
    pub fn validate(&self) -> Result<(), String> {
        if self.new_participant.trim().is_empty() {
            return Err("new_participant must not be empty".into());
        }
        validate_optional_non_empty("source", self.source.as_deref())?;
        Ok(())
    }
}

/// Request body for removing an attendee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveParticipantRequest {
    pub attendee_id: AttendeeId,
}

/// Request body for setting session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStateRequest {
    pub state: SessionState,
}

/// Request body for sharing a file into a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFileRequest {
    pub path: String,
    #[serde(default)]
    pub reference_id: Option<ReferenceId>,
    #[serde(default)]
    pub talk_meta_data: Option<FileShareMetaData>,
}

impl ShareFileRequest {
    /// Validate file-sharing inputs before issuing a remote mutation.
    pub fn validate(&self) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("path must not be empty".into());
        }
        if let Some(reference_id) = &self.reference_id
            && reference_id.0.trim().is_empty()
        {
            return Err("reference_id must not be empty when provided".into());
        }
        Ok(())
    }
}

/// Optional chat metadata for file shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileShareMetaData {
    #[serde(default)]
    pub message_type: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub reply_to: Option<MessageId>,
}

/// Conversation summary or detail record.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub token: ConversationToken,
    #[serde(rename = "type")]
    pub conversation_type: ConversationType,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub participant_type: Option<ParticipantType>,
    #[serde(default)]
    pub attendee_id: Option<AttendeeId>,
    #[serde(default)]
    pub actor_type: Option<AttendeeActorType>,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub permissions: Option<u64>,
    #[serde(default)]
    pub attendee_permissions: Option<u64>,
    #[serde(default)]
    pub participant_flags: Option<u64>,
    #[serde(default)]
    pub read_only: Option<u8>,
    #[serde(default)]
    pub listable: Option<u8>,
    #[serde(default)]
    pub message_expiration: Option<u64>,
    #[serde(default)]
    pub last_ping: Option<u64>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub has_password: Option<bool>,
    #[serde(default)]
    pub has_call: Option<bool>,
    #[serde(default)]
    pub call_flag: Option<u64>,
    #[serde(default)]
    pub can_start_call: Option<bool>,
    #[serde(default)]
    pub can_delete_conversation: Option<bool>,
    #[serde(default)]
    pub can_leave_conversation: Option<bool>,
    #[serde(default)]
    pub last_activity: Option<u64>,
    #[serde(default)]
    pub is_favorite: Option<bool>,
    #[serde(default)]
    pub notification_level: Option<u8>,
    #[serde(default)]
    pub lobby_state: Option<u8>,
    #[serde(default)]
    pub lobby_timer: Option<u64>,
    #[serde(default)]
    pub sip_enabled: Option<u8>,
    #[serde(default)]
    pub unread_messages: Option<u64>,
    #[serde(default)]
    pub unread_mention: Option<bool>,
    #[serde(default)]
    pub unread_mention_direct: Option<bool>,
    #[serde(default)]
    pub last_read_message: Option<MessageId>,
    #[serde(default)]
    pub last_common_read_message: Option<MessageId>,
    #[serde(default)]
    pub last_message: Option<ChatMessage>,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub object_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_icon: Option<String>,
    #[serde(default)]
    pub status_message: Option<String>,
    #[serde(default)]
    pub status_clear_at: Option<u64>,
    #[serde(default)]
    pub avatar_version: Option<String>,
    #[serde(default)]
    pub is_custom_avatar: Option<bool>,
    #[serde(default)]
    pub call_start_time: Option<u64>,
    #[serde(default)]
    pub call_recording: Option<u8>,
    #[serde(default)]
    pub recording_consent: Option<u8>,
    #[serde(default)]
    pub mention_permissions: Option<u8>,
    #[serde(default)]
    pub is_archived: Option<bool>,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("token", &"[REDACTED]")
            .field("conversation_type", &self.conversation_type)
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("description", &self.description)
            .field("participant_type", &self.participant_type)
            .field("attendee_id", &self.attendee_id)
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id)
            .field("permissions", &self.permissions)
            .field("attendee_permissions", &self.attendee_permissions)
            .field("participant_flags", &self.participant_flags)
            .field("read_only", &self.read_only)
            .field("listable", &self.listable)
            .field("message_expiration", &self.message_expiration)
            .field("last_ping", &self.last_ping)
            .field("session_id", &self.session_id)
            .field("has_password", &self.has_password)
            .field("has_call", &self.has_call)
            .field("call_flag", &self.call_flag)
            .field("can_start_call", &self.can_start_call)
            .field("can_delete_conversation", &self.can_delete_conversation)
            .field("can_leave_conversation", &self.can_leave_conversation)
            .field("last_activity", &self.last_activity)
            .field("is_favorite", &self.is_favorite)
            .field("notification_level", &self.notification_level)
            .field("lobby_state", &self.lobby_state)
            .field("lobby_timer", &self.lobby_timer)
            .field("sip_enabled", &self.sip_enabled)
            .field("unread_messages", &self.unread_messages)
            .field("unread_mention", &self.unread_mention)
            .field("unread_mention_direct", &self.unread_mention_direct)
            .field("last_read_message", &self.last_read_message)
            .field("last_common_read_message", &self.last_common_read_message)
            .field("last_message", &self.last_message)
            .field("object_type", &self.object_type)
            .field("object_id", &self.object_id)
            .field("status", &self.status)
            .field("status_icon", &self.status_icon)
            .field("status_message", &self.status_message)
            .field("status_clear_at", &self.status_clear_at)
            .field("avatar_version", &self.avatar_version)
            .field("is_custom_avatar", &self.is_custom_avatar)
            .field("call_start_time", &self.call_start_time)
            .field("call_recording", &self.call_recording)
            .field("recording_consent", &self.recording_consent)
            .field("mention_permissions", &self.mention_permissions)
            .field("is_archived", &self.is_archived)
            .finish()
    }
}

/// Chat message returned by the Talk API.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub id: MessageId,
    pub token: ConversationToken,
    pub actor_type: ChatActorType,
    pub actor_id: String,
    #[serde(default)]
    pub actor_display_name: String,
    pub timestamp: u64,
    #[serde(default)]
    pub system_message: String,
    #[serde(default)]
    pub message_type: String,
    #[serde(default)]
    pub is_replyable: Option<bool>,
    #[serde(default)]
    pub reference_id: Option<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub message_parameters: serde_json::Value,
    #[serde(default)]
    pub expiration_timestamp: Option<u64>,
    #[serde(default)]
    pub parent: Option<serde_json::Value>,
    #[serde(default)]
    pub reactions: BTreeMap<String, u64>,
    #[serde(default)]
    pub reactions_self: Vec<String>,
    #[serde(default)]
    pub markdown: Option<bool>,
    #[serde(default)]
    pub last_edit_actor_type: Option<ChatActorType>,
    #[serde(default)]
    pub last_edit_actor_id: Option<String>,
    #[serde(default)]
    pub last_edit_actor_display_name: Option<String>,
    #[serde(default)]
    pub last_edit_timestamp: Option<u64>,
    #[serde(default)]
    pub silent: Option<bool>,
}

impl std::fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatMessage")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("actor_type", &self.actor_type)
            .field("actor_id", &self.actor_id)
            .field("actor_display_name", &self.actor_display_name)
            .field("timestamp", &self.timestamp)
            .field("system_message", &self.system_message)
            .field("message_type", &self.message_type)
            .field("is_replyable", &self.is_replyable)
            .field("reference_id", &self.reference_id)
            .field("message", &self.message)
            .field("message_parameters", &self.message_parameters)
            .field("expiration_timestamp", &self.expiration_timestamp)
            .field("parent", &self.parent)
            .field("reactions", &self.reactions)
            .field("reactions_self", &self.reactions_self)
            .field("markdown", &self.markdown)
            .field("last_edit_actor_type", &self.last_edit_actor_type)
            .field("last_edit_actor_id", &self.last_edit_actor_id)
            .field(
                "last_edit_actor_display_name",
                &self.last_edit_actor_display_name,
            )
            .field("last_edit_timestamp", &self.last_edit_timestamp)
            .field("silent", &self.silent)
            .finish()
    }
}

/// Result of fetching or long-polling chat messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessagesPage {
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub last_given: Option<MessageId>,
    #[serde(default)]
    pub last_common_read: Option<MessageId>,
    #[serde(default)]
    pub not_modified: bool,
}

/// Reaction entry for a chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reaction {
    pub actor_type: ChatActorType,
    pub actor_id: String,
    pub actor_display_name: String,
    pub timestamp: u64,
}

/// Participant row returned by the participants API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    pub attendee_id: AttendeeId,
    pub actor_type: AttendeeActorType,
    pub actor_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub participant_type: Option<ParticipantType>,
    #[serde(default)]
    pub last_ping: Option<u64>,
    #[serde(default)]
    pub in_call: Option<u64>,
    #[serde(default)]
    pub permissions: Option<u64>,
    #[serde(default)]
    pub attendee_permissions: Option<u64>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_ids: Vec<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_icon: Option<String>,
    #[serde(default)]
    pub status_message: Option<String>,
    #[serde(default)]
    pub room_token: Option<ConversationToken>,
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub call_id: Option<String>,
}

/// Connected participant returned by the call-state API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallParticipant {
    pub actor_type: AttendeeActorType,
    pub actor_id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub last_ping: Option<u64>,
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Minimal share response for files shared into a conversation.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileShareResponse {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub item_type: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for FileShareResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileShareResponse")
            .field("id", &self.id)
            .field("item_type", &self.item_type)
            .field("path", &self.path)
            .field("url", &self.url)
            .field("token", &"[REDACTED]")
            .field("extra", &self.extra)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileShareResponseObject {
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    id: Option<u64>,
    #[serde(default)]
    item_type: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl From<FileShareResponseObject> for FileShareResponse {
    fn from(value: FileShareResponseObject) -> Self {
        Self {
            id: value.id,
            item_type: value.item_type,
            path: value.path,
            url: value.url,
            token: value.token,
            extra: value.extra,
        }
    }
}

impl<'de> Deserialize<'de> for FileShareResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Id(#[serde(deserialize_with = "deserialize_u64")] u64),
            Object(FileShareResponseObject),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Id(id) => Ok(Self {
                id: Some(id),
                ..Self::default()
            }),
            Repr::Object(object) => Ok(object.into()),
        }
    }
}

const fn default_true() -> bool {
    true
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    value
        .map(|value| deserialize_u64_value(&value).map_err(serde::de::Error::custom))
        .transpose()
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    deserialize_u64_value(&value).map_err(serde::de::Error::custom)
}

fn deserialize_u64_value(value: &serde_json::Value) -> Result<u64, String> {
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| "share id must be a positive integer".into()),
        serde_json::Value::String(value) => value
            .parse::<u64>()
            .map_err(|error| format!("share id must be a positive integer: {error}")),
        other => Err(format!("share id must be a string or integer, got {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserve_unknown_conversation_type() {
        let conversation_type = ConversationType::from(99);
        assert!(matches!(conversation_type, ConversationType::Unknown(99)));
        assert_eq!(u8::from(conversation_type), 99);
    }

    #[test]
    fn validate_chat_query_limits() {
        let query = ChatMessagesQuery {
            limit: Some(201),
            ..ChatMessagesQuery::default()
        };
        assert!(query.validate().is_err());

        let valid = ChatMessagesQuery {
            limit: Some(200),
            timeout_secs: Some(60),
            ..ChatMessagesQuery::default()
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn parse_conversation_token() {
        let token = ConversationToken::new("abc123").expect("token");
        assert_eq!(token.as_str(), "abc123");
        assert!(ConversationToken::new("   ").is_err());
    }

    #[test]
    fn trim_identifier_wrappers() {
        let token = ConversationToken::new("  room-1  ").expect("token");
        assert_eq!(token.as_str(), "room-1");

        let reference_id = ReferenceId::new("  ref-1  ").expect("reference id");
        assert_eq!(reference_id.0, "ref-1");
    }

    #[test]
    fn reject_unknown_room_type_for_creation() {
        let request = CreateConversationRequest {
            room_type: ConversationType::Unknown(99),
            invite: None,
            source: None,
            room_name: None,
            object_type: None,
            object_id: None,
            password: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn reject_blank_mutation_payloads() {
        assert!(
            SendChatMessageRequest {
                message: "   ".into(),
                actor_display_name: None,
                reply_to: None,
                reference_id: None,
                silent: false,
            }
            .validate()
            .is_err()
        );

        assert!(
            ReactionRequest {
                reaction: "  ".into()
            }
            .validate()
            .is_err()
        );

        assert!(
            AddParticipantRequest {
                new_participant: "  ".into(),
                source: None,
            }
            .validate()
            .is_err()
        );

        assert!(
            ShareFileRequest {
                path: "  ".into(),
                reference_id: None,
                talk_meta_data: None,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn file_share_response_accepts_numeric_or_object_payloads() {
        let numeric: FileShareResponse =
            serde_json::from_value(serde_json::json!(17)).expect("numeric share response");
        assert_eq!(numeric.id, Some(17));
        assert!(numeric.token.is_none());

        let object: FileShareResponse = serde_json::from_value(serde_json::json!({
            "id": "18",
            "itemType": "file",
            "path": "/Documents/spec.pdf",
            "token": "room123"
        }))
        .expect("object share response");
        assert_eq!(object.id, Some(18));
        assert_eq!(object.item_type.as_deref(), Some("file"));
        assert_eq!(object.token.as_deref(), Some("room123"));
    }
}
