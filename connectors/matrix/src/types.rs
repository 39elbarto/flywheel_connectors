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

    /// Inbound event policy used when projecting sync results for agent delivery.
    #[serde(default)]
    pub inbound_policy: MatrixInboundPolicy,

    /// End-to-end encryption readiness and trust surface.
    #[serde(default)]
    pub e2ee: MatrixE2eeConfig,

    /// Explicit sync-state persistence and restore surface.
    #[serde(default)]
    pub state_persistence: MatrixStatePersistenceConfig,

    /// Optional supervised background sync loop configuration.
    #[serde(default)]
    pub supervised_sync: MatrixSupervisedSyncConfig,
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

const fn default_require_mention() -> bool {
    true
}

const fn default_process_reactions() -> bool {
    true
}

const fn default_strip_bot_mentions() -> bool {
    true
}

const fn default_direct_message_member_limit() -> usize {
    2
}

fn default_approval_reaction_keys() -> Vec<String> {
    vec!["approve".into(), "approved".into(), "+1".into()]
}

/// Configured Matrix inbound policy for sync/event projection.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixInboundPolicy {
    /// Optional sender allowlist. Empty means any sender is eligible.
    #[serde(default)]
    pub allowed_users: Vec<String>,

    /// Optional Matrix user ID for the connector/bot account.
    #[serde(default)]
    pub bot_user_id: Option<String>,

    /// Require explicit bot mention in room messages unless the room is allowlisted.
    #[serde(default = "default_require_mention")]
    pub require_mention: bool,

    /// Rooms where non-mentioned messages may be delivered.
    #[serde(default)]
    pub free_response_rooms: Vec<String>,

    /// Rooms classified as direct messages, where mention gating is not required.
    #[serde(default)]
    pub direct_message_rooms: Vec<String>,

    /// Matrix thread roots where the connector has already participated.
    #[serde(default)]
    pub thread_participation_roots: Vec<String>,

    /// Whether reaction events are projected for approval/routing consumers.
    #[serde(default = "default_process_reactions")]
    pub process_reactions: bool,

    /// Workflow routing and redaction policy. Flattening preserves the external config shape.
    #[serde(default, flatten)]
    pub workflow: MatrixWorkflowPolicy,

    /// How encrypted events are represented while verified E2EE is not implemented.
    #[serde(default)]
    pub encrypted_events: MatrixEncryptedEventPolicy,
}

impl Default for MatrixInboundPolicy {
    fn default() -> Self {
        Self {
            allowed_users: Vec::new(),
            bot_user_id: None,
            require_mention: true,
            free_response_rooms: Vec::new(),
            direct_message_rooms: Vec::new(),
            thread_participation_roots: Vec::new(),
            process_reactions: true,
            workflow: MatrixWorkflowPolicy::default(),
            encrypted_events: MatrixEncryptedEventPolicy::FailClosed,
        }
    }
}

/// Matrix workflow policy fields that keep inbound projection ergonomic for users.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixWorkflowPolicy {
    /// Derive direct-message rooms from membership state when the bot is one of a small room's joined users.
    #[serde(default)]
    pub dynamic_direct_message_detection: bool,

    /// Maximum joined members for dynamic direct-message detection.
    #[serde(default = "default_direct_message_member_limit")]
    pub direct_message_member_limit: usize,

    /// Remove explicit bot mention text from the delivery body while preserving the raw Matrix body.
    #[serde(default = "default_strip_bot_mentions")]
    pub strip_bot_mentions: bool,

    /// Reaction keys that should be interpreted as approval reactions from allowed senders.
    #[serde(default = "default_approval_reaction_keys")]
    pub approval_reaction_keys: Vec<String>,

    /// Optional maximum inbound media size. Oversized media messages are dropped before agent delivery.
    #[serde(default)]
    pub media_max_bytes: Option<u64>,
}

impl Default for MatrixWorkflowPolicy {
    fn default() -> Self {
        Self {
            dynamic_direct_message_detection: false,
            direct_message_member_limit: default_direct_message_member_limit(),
            strip_bot_mentions: true,
            approval_reaction_keys: default_approval_reaction_keys(),
            media_max_bytes: None,
        }
    }
}

const fn default_supervised_sync_poll_interval_ms() -> u64 {
    30_000
}

const fn default_supervised_sync_timeout_ms() -> u32 {
    30_000
}

/// Disabled-by-default background sync loop configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MatrixSupervisedSyncConfig {
    /// Whether subscription should start the supervised sync worker.
    #[serde(default)]
    pub enabled: bool,

    /// Delay between successful incremental sync calls.
    #[serde(default = "default_supervised_sync_poll_interval_ms")]
    pub poll_interval_ms: u64,

    /// Matrix `/sync` long-poll timeout.
    #[serde(default = "default_supervised_sync_timeout_ms")]
    pub timeout_ms: u32,

    /// Backoff and failure budget for recoverable sync failures.
    #[serde(default)]
    pub supervisor: fcp_sdk::runtime::SupervisorConfig,
}

impl Default for MatrixSupervisedSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_ms: default_supervised_sync_poll_interval_ms(),
            timeout_ms: default_supervised_sync_timeout_ms(),
            supervisor: fcp_sdk::runtime::SupervisorConfig::default(),
        }
    }
}

const fn default_state_persistence_max_tracked_rooms() -> usize {
    1_024
}

const fn default_state_persistence_max_thread_roots() -> usize {
    4_096
}

/// Durable-state backend contract for Matrix sync cursors and routing context.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatrixStatePersistenceBackend {
    /// Connector-local state is in-memory only and resets on configure.
    #[default]
    InMemory,
    /// The host persists `matrix.sync` `tracked_state` and passes a restore snapshot on configure.
    HostManagedSnapshot,
}

/// Explicit Matrix state persistence configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixStatePersistenceConfig {
    /// Whether durable host-managed state restore is requested.
    #[serde(default)]
    pub enabled: bool,

    /// Persistence backend contract.
    #[serde(default)]
    pub backend: MatrixStatePersistenceBackend,

    /// Zone scope for restored state. Required when enabled.
    #[serde(default)]
    pub zone_id: Option<String>,

    /// Matrix account scope for restored state. Required when enabled.
    #[serde(default)]
    pub account_user_id: Option<String>,

    /// Optional Matrix device scope for restored state.
    #[serde(default)]
    pub device_id: Option<String>,

    /// Host-provided restore snapshot.
    #[serde(default)]
    pub restore: MatrixStateRestoreConfig,

    /// Bounded in-memory tracking limits for restored and future state.
    #[serde(default)]
    pub limits: MatrixStatePersistenceLimits,
}

impl Default for MatrixStatePersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: MatrixStatePersistenceBackend::InMemory,
            zone_id: None,
            account_user_id: None,
            device_id: None,
            restore: MatrixStateRestoreConfig::default(),
            limits: MatrixStatePersistenceLimits::default(),
        }
    }
}

/// Host-provided state restore snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixStateRestoreConfig {
    /// Last Matrix sync token restored from host-managed state.
    #[serde(default)]
    pub last_sync_token: Option<String>,

    /// Dynamic direct-message room classifications restored from host-managed state.
    #[serde(default)]
    pub dynamic_direct_message_rooms: Vec<String>,

    /// Participated Matrix thread roots restored from host-managed state.
    #[serde(default)]
    pub thread_participation_roots: Vec<String>,
}

/// Bounds for host-restored and connector-tracked state.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixStatePersistenceLimits {
    /// Maximum tracked room summaries retained in memory.
    #[serde(default = "default_state_persistence_max_tracked_rooms")]
    pub max_tracked_rooms: usize,

    /// Maximum thread roots retained in memory.
    #[serde(default = "default_state_persistence_max_thread_roots")]
    pub max_thread_participation_roots: usize,
}

impl Default for MatrixStatePersistenceLimits {
    fn default() -> Self {
        Self {
            max_tracked_rooms: default_state_persistence_max_tracked_rooms(),
            max_thread_participation_roots: default_state_persistence_max_thread_roots(),
        }
    }
}

/// Matrix encrypted-event behavior until verified E2EE support is implemented.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatrixEncryptedEventPolicy {
    /// Do not emit encrypted events as agent input.
    #[default]
    FailClosed,
    /// Emit only redacted metadata for encrypted events.
    MetadataOnly,
}

const fn default_e2ee_require_verified_device_trust() -> bool {
    true
}

const fn default_e2ee_require_cross_signing() -> bool {
    true
}

const fn default_e2ee_require_room_key_backup() -> bool {
    true
}

const fn default_undecrypted_retry_max_attempts() -> u32 {
    3
}

const fn default_undecrypted_retry_after_ms() -> u64 {
    60_000
}

/// Operator-provided E2EE readiness inputs. These are status hints only until
/// a verified Matrix crypto implementation is wired into the connector.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixE2eeConfig {
    /// Request verified decryption. This is denied until audited crypto support exists.
    #[serde(default)]
    pub verified_decryption_requested: bool,

    /// Expected Matrix account user ID for future device-bound verification.
    #[serde(default)]
    pub account_user_id: Option<String>,

    /// Stable Matrix device ID for future device-bound verification.
    #[serde(default)]
    pub device_id: Option<String>,

    /// Verification requirements that must pass before decrypted delivery is safe.
    #[serde(flatten)]
    pub trust: MatrixE2eeTrustRequirements,

    /// Secretless trust-state signals imported from the Matrix crypto store/device-key surface.
    #[serde(default)]
    pub trust_state: MatrixE2eeTrustStateConfig,

    /// Recovery-key readiness status without storing or logging recovery secrets.
    #[serde(default)]
    pub recovery: MatrixE2eeRecoveryConfig,

    /// Room-key backup readiness status without storing or logging backup secrets.
    #[serde(default)]
    pub room_key_backup: MatrixE2eeBackupConfig,

    /// Classification policy for encrypted events that cannot be decrypted.
    #[serde(default)]
    pub undecrypted_retry: MatrixUndecryptedRetryConfig,
}

/// Trust requirements for future verified Matrix E2EE delivery.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixE2eeTrustRequirements {
    /// Require a verified device trust chain before decrypted delivery.
    #[serde(default = "default_e2ee_require_verified_device_trust")]
    pub require_verified_device_trust: bool,

    /// Require cross-signing before decrypted delivery.
    #[serde(default = "default_e2ee_require_cross_signing")]
    pub require_cross_signing: bool,

    /// Require room-key backup/recovery readiness before decrypted delivery.
    #[serde(default = "default_e2ee_require_room_key_backup")]
    pub require_room_key_backup: bool,
}

impl Default for MatrixE2eeTrustRequirements {
    fn default() -> Self {
        Self {
            require_verified_device_trust: true,
            require_cross_signing: true,
            require_room_key_backup: true,
        }
    }
}

/// Secretless E2EE trust-state inputs. These are readiness signals only; they
/// deliberately do not contain device private keys, room keys, recovery keys, or ciphertext.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixE2eeTrustStateConfig {
    /// Own-device verification status for the configured account/device.
    #[serde(default)]
    pub own_device: MatrixE2eeMaterialStatus,

    /// Device-key import status from `/keys/query`.
    #[serde(default)]
    pub device_keys: MatrixE2eeMaterialStatus,

    /// Device-list freshness for tracked users.
    #[serde(default)]
    pub device_list: MatrixE2eeDeviceListConfig,

    /// Cross-signing key verification status.
    #[serde(default)]
    pub cross_signing: MatrixE2eeMaterialStatus,

    /// Users whose device lists are tracked by the crypto store.
    #[serde(default)]
    pub tracked_users: Vec<String>,

    /// Rooms whose encrypted sessions are tracked by the crypto store.
    #[serde(default)]
    pub tracked_rooms: Vec<String>,
}

/// Device-list freshness classification for Matrix E2EE trust state.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixE2eeDeviceListConfig {
    /// Freshness status for tracked device lists.
    #[serde(default)]
    pub status: MatrixE2eeDeviceListStatus,

    /// Optional age of the last successful device-list refresh.
    #[serde(default)]
    pub last_refresh_age_ms: Option<u64>,
}

impl Default for MatrixE2eeDeviceListConfig {
    fn default() -> Self {
        Self {
            status: MatrixE2eeDeviceListStatus::Unknown,
            last_refresh_age_ms: None,
        }
    }
}

/// Secretless device-list freshness label.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatrixE2eeDeviceListStatus {
    /// The connector has not received a trusted freshness signal.
    #[default]
    Unknown,
    /// No usable device list was imported.
    Missing,
    /// Device lists exist but must be refreshed before trusted decrypt.
    Stale,
    /// Device lists are fresh enough for trust evaluation.
    Fresh,
}

/// Secretless status labels for E2EE material readiness.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatrixE2eeMaterialStatus {
    /// The connector has not received a trustworthy status signal.
    #[default]
    Unknown,
    /// The required material is absent.
    Missing,
    /// Material exists but has not been verified by the connector.
    PresentUnverified,
    /// Material has been verified by a future crypto implementation.
    Verified,
}

/// Recovery-key readiness without the key material itself.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixE2eeRecoveryConfig {
    /// Recovery material status.
    #[serde(default)]
    pub status: MatrixE2eeMaterialStatus,
}

/// Room-key backup readiness without backup secrets.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixE2eeBackupConfig {
    /// Backup material status.
    #[serde(default)]
    pub status: MatrixE2eeMaterialStatus,

    /// Optional non-secret Matrix backup version identifier.
    #[serde(default)]
    pub backup_version: Option<String>,
}

/// Retry classification for encrypted events that remain undecrypted.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MatrixUndecryptedRetryConfig {
    /// Number of retryable classifications before the event is treated as final failure.
    #[serde(default = "default_undecrypted_retry_max_attempts")]
    pub max_attempts: u32,

    /// Recommended delay before retrying key/share recovery checks.
    #[serde(default = "default_undecrypted_retry_after_ms")]
    pub retry_after_ms: u64,
}

impl Default for MatrixUndecryptedRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_undecrypted_retry_max_attempts(),
            retry_after_ms: default_undecrypted_retry_after_ms(),
        }
    }
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
// E2EE Device Keys
// ─────────────────────────────────────────────────────────────────────────────

/// Matrix `/keys/query` request body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixDeviceKeysQueryRequest {
    /// Users/devices whose device keys should be fetched. An empty device list asks for all devices.
    pub device_keys: std::collections::BTreeMap<String, Vec<String>>,

    /// Optional server-side timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,

    /// Optional sync token for incremental device-list freshness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Matrix `/keys/query` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixDeviceKeysQueryResponse {
    /// Homeserver failures by server name.
    #[serde(default)]
    pub failures: std::collections::BTreeMap<String, serde_json::Value>,

    /// Device keys by user ID and device ID.
    #[serde(default)]
    pub device_keys:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, MatrixDeviceKey>>,

    /// Cross-signing master keys by user ID.
    #[serde(default)]
    pub master_keys: std::collections::BTreeMap<String, MatrixCrossSigningKey>,

    /// Cross-signing self-signing keys by user ID.
    #[serde(default)]
    pub self_signing_keys: std::collections::BTreeMap<String, MatrixCrossSigningKey>,

    /// Cross-signing user-signing keys by user ID.
    #[serde(default)]
    pub user_signing_keys: std::collections::BTreeMap<String, MatrixCrossSigningKey>,
}

/// Matrix `/keys/upload` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixDeviceKeysUploadResponse {
    /// One-time key counts by algorithm.
    #[serde(default)]
    pub one_time_key_counts: std::collections::BTreeMap<String, u64>,
}

/// Matrix `/keys/claim` request body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixDeviceKeysClaimRequest {
    /// One-time key algorithms requested by user ID and device ID.
    pub one_time_keys:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,

    /// Optional server-side timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Matrix `/keys/claim` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixDeviceKeysClaimResponse {
    /// Homeserver failures by server name.
    #[serde(default)]
    pub failures: std::collections::BTreeMap<String, serde_json::Value>,

    /// Claimed one-time keys by user ID, device ID, and key ID. Values are public encrypted payloads
    /// from the homeserver response and are never persisted by this connector in this slice.
    #[serde(default)]
    pub one_time_keys: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, serde_json::Value>>,
    >,
}

/// Matrix room-key backup version response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixRoomKeyBackupVersionResponse {
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub auth_data: serde_json::Value,
    #[serde(default)]
    pub count: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

/// Matrix room-key backup upload response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixRoomKeyBackupUploadResponse {
    #[serde(default)]
    pub count: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
}

/// Public Matrix device key record. Secret key material is never present in this shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixDeviceKey {
    pub user_id: String,
    pub device_id: String,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub signatures: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub unsigned: serde_json::Value,
}

/// Public Matrix cross-signing key record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MatrixCrossSigningKey {
    pub user_id: String,
    #[serde(default)]
    pub usage: Vec<String>,
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub signatures: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
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
    #[allow(clippy::too_many_lines)]
    fn deserialize_config_with_inbound_policy() {
        let json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "inbound_policy": {
                "allowed_users": ["@alice:matrix.org"],
                "bot_user_id": "@bot:matrix.org",
                "require_mention": true,
                "free_response_rooms": ["!ops:matrix.org"],
                "direct_message_rooms": ["!dm:matrix.org"],
                "dynamic_direct_message_detection": true,
                "direct_message_member_limit": 3,
                "thread_participation_roots": ["$thread-root"],
                "strip_bot_mentions": false,
                "process_reactions": false,
                "approval_reaction_keys": ["approve", "ship"],
                "media_max_bytes": 1_048_576,
                "encrypted_events": "metadata_only"
            },
            "e2ee": {
                "verified_decryption_requested": true,
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123",
                "trust_state": {
                    "own_device": "verified",
                    "device_keys": "verified",
                    "device_list": {
                        "status": "fresh",
                        "last_refresh_age_ms": 25
                    },
                    "cross_signing": "present_unverified",
                    "tracked_users": ["@alice:matrix.org"],
                    "tracked_rooms": ["!secure:matrix.org"]
                },
                "recovery": { "status": "present_unverified" },
                "room_key_backup": {
                    "status": "missing",
                    "backup_version": "1"
                },
                "undecrypted_retry": {
                    "max_attempts": 5,
                    "retry_after_ms": 250
                }
            }
        });
        let config: MatrixConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            config.inbound_policy.allowed_users,
            vec!["@alice:matrix.org"]
        );
        assert_eq!(
            config.inbound_policy.bot_user_id.as_deref(),
            Some("@bot:matrix.org")
        );
        assert_eq!(
            config.inbound_policy.free_response_rooms,
            vec!["!ops:matrix.org"]
        );
        assert_eq!(
            config.inbound_policy.direct_message_rooms,
            vec!["!dm:matrix.org"]
        );
        assert!(
            config
                .inbound_policy
                .workflow
                .dynamic_direct_message_detection
        );
        assert_eq!(
            config.inbound_policy.workflow.direct_message_member_limit,
            3
        );
        assert_eq!(
            config.inbound_policy.thread_participation_roots,
            vec!["$thread-root"]
        );
        assert!(!config.inbound_policy.workflow.strip_bot_mentions);
        assert!(!config.inbound_policy.process_reactions);
        assert_eq!(
            config.inbound_policy.workflow.approval_reaction_keys,
            vec!["approve", "ship"]
        );
        assert_eq!(
            config.inbound_policy.workflow.media_max_bytes,
            Some(1_048_576)
        );
        assert_eq!(
            config.inbound_policy.encrypted_events,
            MatrixEncryptedEventPolicy::MetadataOnly
        );
        assert!(config.e2ee.verified_decryption_requested);
        assert_eq!(
            config.e2ee.account_user_id.as_deref(),
            Some("@bot:matrix.org")
        );
        assert_eq!(config.e2ee.device_id.as_deref(), Some("DEVICE123"));
        assert_eq!(
            config.e2ee.trust_state.own_device,
            MatrixE2eeMaterialStatus::Verified
        );
        assert_eq!(
            config.e2ee.trust_state.device_keys,
            MatrixE2eeMaterialStatus::Verified
        );
        assert_eq!(
            config.e2ee.trust_state.device_list.status,
            MatrixE2eeDeviceListStatus::Fresh
        );
        assert_eq!(
            config.e2ee.trust_state.device_list.last_refresh_age_ms,
            Some(25)
        );
        assert_eq!(
            config.e2ee.trust_state.cross_signing,
            MatrixE2eeMaterialStatus::PresentUnverified
        );
        assert_eq!(
            config.e2ee.trust_state.tracked_users,
            vec!["@alice:matrix.org"]
        );
        assert_eq!(
            config.e2ee.trust_state.tracked_rooms,
            vec!["!secure:matrix.org"]
        );
        assert_eq!(
            config.e2ee.recovery.status,
            MatrixE2eeMaterialStatus::PresentUnverified
        );
        assert_eq!(
            config.e2ee.room_key_backup.status,
            MatrixE2eeMaterialStatus::Missing
        );
        assert_eq!(
            config.e2ee.room_key_backup.backup_version.as_deref(),
            Some("1")
        );
        assert_eq!(config.e2ee.undecrypted_retry.max_attempts, 5);
        assert_eq!(config.e2ee.undecrypted_retry.retry_after_ms, 250);
    }

    #[test]
    fn deserialize_config_with_state_persistence() {
        let json = serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "state_persistence": {
                "enabled": true,
                "backend": "host_managed_snapshot",
                "zone_id": "z:work",
                "account_user_id": "@bot:matrix.org",
                "device_id": "DEVICE123",
                "restore": {
                    "last_sync_token": "batch_restore",
                    "dynamic_direct_message_rooms": ["!dm:matrix.org"],
                    "thread_participation_roots": ["$thread-root"]
                },
                "limits": {
                    "max_tracked_rooms": 128,
                    "max_thread_participation_roots": 256
                }
            }
        });
        let config: MatrixConfig = serde_json::from_value(json).unwrap();
        assert!(config.state_persistence.enabled);
        assert_eq!(
            config.state_persistence.backend,
            MatrixStatePersistenceBackend::HostManagedSnapshot
        );
        assert_eq!(config.state_persistence.zone_id.as_deref(), Some("z:work"));
        assert_eq!(
            config.state_persistence.account_user_id.as_deref(),
            Some("@bot:matrix.org")
        );
        assert_eq!(
            config.state_persistence.device_id.as_deref(),
            Some("DEVICE123")
        );
        assert_eq!(
            config.state_persistence.restore.last_sync_token.as_deref(),
            Some("batch_restore")
        );
        assert_eq!(
            config
                .state_persistence
                .restore
                .dynamic_direct_message_rooms,
            vec!["!dm:matrix.org"]
        );
        assert_eq!(
            config.state_persistence.restore.thread_participation_roots,
            vec!["$thread-root"]
        );
        assert_eq!(config.state_persistence.limits.max_tracked_rooms, 128);
        assert_eq!(
            config
                .state_persistence
                .limits
                .max_thread_participation_roots,
            256
        );
    }

    #[test]
    fn inbound_policy_defaults_fail_closed_for_background_delivery() {
        let config: MatrixConfig = serde_json::from_value(serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" }
        }))
        .unwrap();

        assert!(config.inbound_policy.allowed_users.is_empty());
        assert!(config.inbound_policy.require_mention);
        assert!(config.inbound_policy.process_reactions);
        assert!(
            !config
                .inbound_policy
                .workflow
                .dynamic_direct_message_detection
        );
        assert_eq!(
            config.inbound_policy.workflow.direct_message_member_limit,
            2
        );
        assert!(config.inbound_policy.workflow.strip_bot_mentions);
        assert_eq!(
            config.inbound_policy.workflow.approval_reaction_keys,
            vec!["approve", "approved", "+1"]
        );
        assert_eq!(config.inbound_policy.workflow.media_max_bytes, None);
        assert_eq!(
            config.inbound_policy.encrypted_events,
            MatrixEncryptedEventPolicy::FailClosed
        );
        assert!(!config.e2ee.verified_decryption_requested);
        assert!(config.e2ee.trust.require_verified_device_trust);
        assert!(config.e2ee.trust.require_cross_signing);
        assert!(config.e2ee.trust.require_room_key_backup);
        assert_eq!(
            config.e2ee.recovery.status,
            MatrixE2eeMaterialStatus::Unknown
        );
        assert_eq!(
            config.e2ee.room_key_backup.status,
            MatrixE2eeMaterialStatus::Unknown
        );
        assert_eq!(config.e2ee.undecrypted_retry.max_attempts, 3);
        assert_eq!(config.e2ee.undecrypted_retry.retry_after_ms, 60_000);
        assert!(!config.state_persistence.enabled);
        assert_eq!(
            config.state_persistence.backend,
            MatrixStatePersistenceBackend::InMemory
        );
        assert_eq!(config.state_persistence.limits.max_tracked_rooms, 1_024);
        assert_eq!(
            config
                .state_persistence
                .limits
                .max_thread_participation_roots,
            4_096
        );
        assert!(!config.supervised_sync.enabled);
        assert_eq!(config.supervised_sync.poll_interval_ms, 30_000);
        assert_eq!(config.supervised_sync.timeout_ms, 30_000);
    }

    #[test]
    fn deserialize_config_with_supervised_sync() {
        let config: MatrixConfig = serde_json::from_value(serde_json::json!({
            "homeserver_url": "https://matrix.org",
            "auth": { "mode": "access_token", "access_token": "tok" },
            "supervised_sync": {
                "enabled": true,
                "poll_interval_ms": 250,
                "timeout_ms": 100,
                "supervisor": {
                    "base_backoff_ms": 10,
                    "max_backoff_ms": 100,
                    "jitter_enabled": false,
                    "max_consecutive_failures": 2
                }
            }
        }))
        .unwrap();

        assert!(config.supervised_sync.enabled);
        assert_eq!(config.supervised_sync.poll_interval_ms, 250);
        assert_eq!(config.supervised_sync.timeout_ms, 100);
        assert_eq!(config.supervised_sync.supervisor.base_backoff_ms, 10);
        assert_eq!(config.supervised_sync.supervisor.max_backoff_ms, 100);
        assert!(!config.supervised_sync.supervisor.jitter_enabled);
        assert_eq!(
            config.supervised_sync.supervisor.max_consecutive_failures,
            2
        );
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
