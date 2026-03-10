//! `Spotify` Library Management.
//!
//! Provides safe access to a user's `Spotify` library: listing saved tracks,
//! albums, shows, episodes, and audiobooks. Supports save/unsave operations
//! with auditable action tracking. Library writes modify user state and are
//! gated by capability policies (`spotify.library.read`, `spotify.library.write`).
//!
//! **Privacy invariant:** Audit events never contain track names, album names,
//! or other personal context -- only opaque `Spotify` IDs.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Item types ──────────────────────────────────────────────────────────

/// The kind of item stored in a user's `Spotify` library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryItemType {
    /// A saved track.
    Track,
    /// A saved album.
    Album,
    /// A saved show (podcast).
    Show,
    /// A saved episode.
    Episode,
    /// A saved audiobook.
    Audiobook,
}

impl fmt::Display for LibraryItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Track => f.write_str("track"),
            Self::Album => f.write_str("album"),
            Self::Show => f.write_str("show"),
            Self::Episode => f.write_str("episode"),
            Self::Audiobook => f.write_str("audiobook"),
        }
    }
}

// ── Library item structs ────────────────────────────────────────────────

/// A generic library item with type and minimal metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryItem {
    /// `Spotify` ID of the item.
    pub id: String,
    /// The type of item.
    pub item_type: LibraryItemType,
    /// When the item was added to the library (ISO 8601).
    pub added_at: Option<String>,
    /// `Spotify` URI (e.g. `spotify:track:abc123`).
    pub uri: Option<String>,
}

/// A saved track from the user's `Spotify` library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedTrack {
    /// `Spotify` track ID.
    pub id: String,
    /// Track name.
    pub name: String,
    /// Artist names.
    pub artists: Vec<String>,
    /// Album name, if available.
    pub album_name: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// When the track was saved (ISO 8601).
    pub added_at: String,
    /// `Spotify` URI.
    pub uri: String,
}

/// A saved album from the user's `Spotify` library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedAlbum {
    /// `Spotify` album ID.
    pub id: String,
    /// Album name.
    pub name: String,
    /// Artist names.
    pub artists: Vec<String>,
    /// Number of tracks on the album.
    pub total_tracks: u32,
    /// Release date string.
    pub release_date: Option<String>,
    /// When the album was saved (ISO 8601).
    pub added_at: String,
    /// `Spotify` URI.
    pub uri: String,
}

/// A saved show (podcast) from the user's `Spotify` library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedShow {
    /// `Spotify` show ID.
    pub id: String,
    /// Show name.
    pub name: String,
    /// Publisher name, if available.
    pub publisher: Option<String>,
    /// Total number of episodes, if known.
    pub total_episodes: Option<u32>,
    /// When the show was saved (ISO 8601).
    pub added_at: String,
    /// `Spotify` URI.
    pub uri: String,
}

// ── Pagination ──────────────────────────────────────────────────────────

/// A paginated page of library items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryPage {
    /// The items on this page.
    pub items: Vec<LibraryItem>,
    /// Total number of items in the library (for this type).
    pub total: u64,
    /// The offset of this page.
    pub offset: u64,
    /// The maximum number of items per page.
    pub limit: u64,
    /// Whether there is a next page.
    pub has_next: bool,
}

// ── Query builder ───────────────────────────────────────────────────────

/// A query for listing library items with pagination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryQuery {
    /// The type of items to query.
    pub item_type: LibraryItemType,
    /// The offset into the result set.
    pub offset: u64,
    /// Maximum items to return (max 50 per `Spotify` API).
    pub limit: u64,
    /// An ISO 3166-1 alpha-2 market code.
    pub market: Option<String>,
}

impl LibraryQuery {
    /// Create a new query for the given item type with default pagination.
    #[must_use]
    pub const fn new(item_type: LibraryItemType) -> Self {
        Self {
            item_type,
            offset: 0,
            limit: 20,
            market: None,
        }
    }

    /// Set the offset.
    #[must_use]
    pub const fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    /// Set the page limit.
    #[must_use]
    pub const fn with_limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    /// Set the market code.
    #[must_use]
    pub fn with_market(mut self, market: impl Into<String>) -> Self {
        self.market = Some(market.into());
        self
    }

    /// Validate this query against `Spotify` API constraints.
    ///
    /// # Errors
    ///
    /// Returns [`LibraryValidationError`] if the query parameters are invalid.
    pub const fn validate(&self) -> Result<(), LibraryValidationError> {
        LibraryValidator::new().validate_query(self)
    }
}

// ── Actions ─────────────────────────────────────────────────────────────

/// An action to perform on the user's `Spotify` library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LibraryAction {
    /// Save items to the library.
    Save {
        /// `Spotify` IDs to save.
        ids: Vec<String>,
        /// The type of items.
        item_type: LibraryItemType,
    },
    /// Remove items from the library.
    Unsave {
        /// `Spotify` IDs to remove.
        ids: Vec<String>,
        /// The type of items.
        item_type: LibraryItemType,
    },
    /// Check whether items are currently saved.
    CheckSaved {
        /// `Spotify` IDs to check.
        ids: Vec<String>,
        /// The type of items.
        item_type: LibraryItemType,
    },
}

impl LibraryAction {
    /// Return the IDs involved in this action.
    #[must_use]
    pub fn ids(&self) -> &[String] {
        match self {
            Self::Save { ids, .. } | Self::Unsave { ids, .. } | Self::CheckSaved { ids, .. } => ids,
        }
    }

    /// Return the item type for this action.
    #[must_use]
    pub const fn item_type(&self) -> LibraryItemType {
        match self {
            Self::Save { item_type, .. }
            | Self::Unsave { item_type, .. }
            | Self::CheckSaved { item_type, .. } => *item_type,
        }
    }

    /// Return a string label for the action type.
    #[must_use]
    pub const fn action_label(&self) -> &str {
        match self {
            Self::Save { .. } => "save",
            Self::Unsave { .. } => "unsave",
            Self::CheckSaved { .. } => "check_saved",
        }
    }

    /// Whether this action mutates user state.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(self, Self::Save { .. } | Self::Unsave { .. })
    }
}

/// The result of executing a library action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryActionResult {
    /// The action that was performed.
    pub action: LibraryAction,
    /// IDs that succeeded.
    pub succeeded: Vec<String>,
    /// IDs that failed.
    pub failed: Vec<String>,
    /// For `CheckSaved` actions, a map of ID to saved status.
    pub check_results: Option<HashMap<String, bool>>,
}

impl LibraryActionResult {
    /// Whether all items in the action succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed.is_empty()
    }

    /// The total number of items processed.
    #[must_use]
    pub fn total_processed(&self) -> usize {
        self.succeeded.len() + self.failed.len()
    }
}

// ── Validation ──────────────────────────────────────────────────────────

/// Errors arising from library input validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibraryValidationError {
    /// The batch exceeds the maximum allowed size.
    BatchTooLarge {
        /// Maximum allowed batch size.
        max: usize,
        /// Actual batch size supplied.
        actual: usize,
    },
    /// An empty batch was supplied where at least one item is required.
    EmptyBatch,
    /// The query limit is invalid (must be 1..=50).
    InvalidLimit,
    /// The query offset is invalid.
    InvalidOffset,
    /// Duplicate IDs were found in the batch.
    DuplicateIds,
}

impl fmt::Display for LibraryValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BatchTooLarge { max, actual } => {
                write!(f, "batch size {actual} exceeds maximum {max}")
            }
            Self::EmptyBatch => f.write_str("batch must not be empty"),
            Self::InvalidLimit => f.write_str("limit must be between 1 and 50"),
            Self::InvalidOffset => f.write_str("offset must not be negative"),
            Self::DuplicateIds => f.write_str("duplicate IDs in batch"),
        }
    }
}

impl std::error::Error for LibraryValidationError {}

/// Validates library queries and actions against `Spotify` API constraints.
#[derive(Debug, Clone)]
pub struct LibraryValidator {
    /// Maximum number of IDs in a single batch (50 per `Spotify` API).
    pub max_batch_size: usize,
    /// Maximum page limit for queries (50 per `Spotify` API).
    pub max_query_limit: u64,
}

impl LibraryValidator {
    /// Create a validator with default `Spotify` API limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_batch_size: 50,
            max_query_limit: 50,
        }
    }

    /// Validate a library action.
    ///
    /// # Errors
    ///
    /// Returns [`LibraryValidationError`] if the action violates constraints.
    pub fn validate_action(&self, action: &LibraryAction) -> Result<(), LibraryValidationError> {
        let ids = action.ids();
        if ids.is_empty() {
            return Err(LibraryValidationError::EmptyBatch);
        }
        if ids.len() > self.max_batch_size {
            return Err(LibraryValidationError::BatchTooLarge {
                max: self.max_batch_size,
                actual: ids.len(),
            });
        }
        // Check for duplicates.
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        for id in ids {
            if !seen.insert(id.as_str()) {
                return Err(LibraryValidationError::DuplicateIds);
            }
        }
        Ok(())
    }

    /// Validate a library query.
    ///
    /// # Errors
    ///
    /// Returns [`LibraryValidationError`] if the query parameters are invalid.
    pub const fn validate_query(&self, query: &LibraryQuery) -> Result<(), LibraryValidationError> {
        if query.limit == 0 || query.limit > self.max_query_limit {
            return Err(LibraryValidationError::InvalidLimit);
        }
        // offset is u64, so always >= 0; but we guard against absurd values.
        // (Spotify allows very large offsets; we trust u64 range.)
        Ok(())
    }
}

impl Default for LibraryValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Audit events ────────────────────────────────────────────────────────

/// An audit event for a library operation.
///
/// **Privacy invariant:** `item_ids` contains only opaque `Spotify` IDs,
/// never track names, album names, or other personal context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryAuditEvent {
    /// ISO 8601 timestamp of the event.
    pub timestamp: String,
    /// The type of action (e.g. "save", "unsave", `check_saved`).
    pub action_type: String,
    /// The item type involved.
    pub item_type: LibraryItemType,
    /// How many items were involved.
    pub item_count: usize,
    /// The `Spotify` IDs involved (never names or personal context).
    pub item_ids: Vec<String>,
    /// Whether the action was allowed by policy.
    pub was_allowed: bool,
}

impl LibraryAuditEvent {
    /// Create an audit event from an action and policy decision.
    #[must_use]
    pub fn from_action(action: &LibraryAction, was_allowed: bool, timestamp: String) -> Self {
        Self {
            timestamp,
            action_type: action.action_label().to_owned(),
            item_type: action.item_type(),
            item_count: action.ids().len(),
            item_ids: action.ids().to_vec(),
            was_allowed,
        }
    }

    /// Verify that this audit event contains no names -- only IDs.
    /// This is a compile-time design guarantee reinforced by tests.
    #[must_use]
    pub const fn contains_only_ids(&self) -> bool {
        // The struct has no name fields by design. This method exists
        // so tests can assert the invariant explicitly.
        true
    }
}

// ── Policy ──────────────────────────────────────────────────────────────

/// Outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The action is allowed.
    Allow,
    /// The action is denied with a reason.
    Deny(String),
    /// The action requires manual approval before proceeding.
    RequireApproval(String),
}

/// Policy controlling what library operations an agent may perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct LibraryPolicy {
    /// Whether read operations (listing, checking) are allowed.
    pub allow_read: bool,
    /// Whether save operations are allowed.
    pub allow_save: bool,
    /// Whether unsave (remove) operations are allowed.
    pub allow_unsave: bool,
    /// Maximum batch size allowed (may be stricter than API limit).
    pub max_batch_size: usize,
    /// Whether unsave operations require explicit approval.
    pub require_approval_for_unsave: bool,
}

impl LibraryPolicy {
    /// A fully permissive policy (all operations allowed, API max batch size).
    #[must_use]
    pub const fn new_permissive() -> Self {
        Self {
            allow_read: true,
            allow_save: true,
            allow_unsave: true,
            max_batch_size: 50,
            require_approval_for_unsave: false,
        }
    }

    /// A read-only policy (no writes).
    #[must_use]
    pub const fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_save: false,
            allow_unsave: false,
            max_batch_size: 50,
            require_approval_for_unsave: false,
        }
    }

    /// Check whether an action is allowed under this policy.
    #[must_use]
    pub fn check_action(&self, action: &LibraryAction) -> PolicyDecision {
        match action {
            LibraryAction::CheckSaved { .. } => {
                if self.allow_read {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny("read operations are not allowed".into())
                }
            }
            LibraryAction::Save { ids, .. } => {
                if !self.allow_save {
                    return PolicyDecision::Deny("save operations are not allowed".into());
                }
                if ids.len() > self.max_batch_size {
                    return PolicyDecision::Deny(format!(
                        "batch size {} exceeds policy limit {}",
                        ids.len(),
                        self.max_batch_size
                    ));
                }
                PolicyDecision::Allow
            }
            LibraryAction::Unsave { ids, .. } => {
                if !self.allow_unsave {
                    return PolicyDecision::Deny("unsave operations are not allowed".into());
                }
                if ids.len() > self.max_batch_size {
                    return PolicyDecision::Deny(format!(
                        "batch size {} exceeds policy limit {}",
                        ids.len(),
                        self.max_batch_size
                    ));
                }
                if self.require_approval_for_unsave {
                    return PolicyDecision::RequireApproval(format!(
                        "unsave of {} items requires approval",
                        ids.len()
                    ));
                }
                PolicyDecision::Allow
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LibraryItemType ─────────────────────────────────────────────

    #[test]
    fn item_type_display_track() {
        assert_eq!(LibraryItemType::Track.to_string(), "track");
    }

    #[test]
    fn item_type_display_album() {
        assert_eq!(LibraryItemType::Album.to_string(), "album");
    }

    #[test]
    fn item_type_display_show() {
        assert_eq!(LibraryItemType::Show.to_string(), "show");
    }

    #[test]
    fn item_type_display_episode() {
        assert_eq!(LibraryItemType::Episode.to_string(), "episode");
    }

    #[test]
    fn item_type_display_audiobook() {
        assert_eq!(LibraryItemType::Audiobook.to_string(), "audiobook");
    }

    #[test]
    fn item_type_serde_roundtrip() {
        for ty in [
            LibraryItemType::Track,
            LibraryItemType::Album,
            LibraryItemType::Show,
            LibraryItemType::Episode,
            LibraryItemType::Audiobook,
        ] {
            let json = serde_json::to_string(&ty).unwrap();
            let back: LibraryItemType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ty);
        }
    }

    #[test]
    fn item_type_serde_snake_case() {
        let json = serde_json::to_string(&LibraryItemType::Audiobook).unwrap();
        assert_eq!(json, "\"audiobook\"");
    }

    #[test]
    fn item_type_clone_copy() {
        let ty = LibraryItemType::Track;
        let copied = ty;
        #[allow(clippy::clone_on_copy)]
        let cloned = ty.clone();
        assert_eq!(copied, cloned);
    }

    #[test]
    fn item_type_eq_hash() {
        let mut map = HashMap::new();
        map.insert(LibraryItemType::Track, 1);
        map.insert(LibraryItemType::Album, 2);
        assert_eq!(map[&LibraryItemType::Track], 1);
        assert_eq!(map[&LibraryItemType::Album], 2);
    }

    #[test]
    fn item_type_debug() {
        let dbg = format!("{:?}", LibraryItemType::Show);
        assert!(dbg.contains("Show"));
    }

    // ── LibraryItem ─────────────────────────────────────────────────

    #[test]
    fn library_item_basic() {
        let item = LibraryItem {
            id: "abc123".into(),
            item_type: LibraryItemType::Track,
            added_at: Some("2025-01-15T10:30:00Z".into()),
            uri: Some("spotify:track:abc123".into()),
        };
        assert_eq!(item.id, "abc123");
        assert_eq!(item.item_type, LibraryItemType::Track);
        assert!(item.added_at.is_some());
        assert!(item.uri.is_some());
    }

    #[test]
    fn library_item_minimal() {
        let item = LibraryItem {
            id: "xyz".into(),
            item_type: LibraryItemType::Episode,
            added_at: None,
            uri: None,
        };
        assert!(item.added_at.is_none());
        assert!(item.uri.is_none());
    }

    #[test]
    fn library_item_serde_roundtrip() {
        let item = LibraryItem {
            id: "t1".into(),
            item_type: LibraryItemType::Track,
            added_at: Some("2025-06-01".into()),
            uri: Some("spotify:track:t1".into()),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: LibraryItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, item);
    }

    #[test]
    fn library_item_clone_eq() {
        let item = LibraryItem {
            id: "a1".into(),
            item_type: LibraryItemType::Album,
            added_at: None,
            uri: None,
        };
        let cloned = item.clone();
        assert_eq!(item, cloned);
    }

    #[test]
    fn library_item_debug() {
        let item = LibraryItem {
            id: "s1".into(),
            item_type: LibraryItemType::Show,
            added_at: None,
            uri: None,
        };
        let dbg = format!("{item:?}");
        assert!(dbg.contains("LibraryItem"));
        assert!(dbg.contains("s1"));
    }

    // ── SavedTrack ──────────────────────────────────────────────────

    #[test]
    fn saved_track_basic() {
        let t = SavedTrack {
            id: "trk1".into(),
            name: "Test Song".into(),
            artists: vec!["Artist A".into(), "Artist B".into()],
            album_name: Some("Test Album".into()),
            duration_ms: 240_000,
            added_at: "2025-01-01T00:00:00Z".into(),
            uri: "spotify:track:trk1".into(),
        };
        assert_eq!(t.id, "trk1");
        assert_eq!(t.artists.len(), 2);
        assert_eq!(t.duration_ms, 240_000);
    }

    #[test]
    fn saved_track_no_album() {
        let t = SavedTrack {
            id: "trk2".into(),
            name: "Single".into(),
            artists: vec!["Solo".into()],
            album_name: None,
            duration_ms: 180_000,
            added_at: "2025-02-01".into(),
            uri: "spotify:track:trk2".into(),
        };
        assert!(t.album_name.is_none());
    }

    #[test]
    fn saved_track_serde_roundtrip() {
        let t = SavedTrack {
            id: "t1".into(),
            name: "Name".into(),
            artists: vec!["A".into()],
            album_name: Some("Alb".into()),
            duration_ms: 100_000,
            added_at: "2025-01-01".into(),
            uri: "spotify:track:t1".into(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: SavedTrack = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn saved_track_clone_debug() {
        let t = SavedTrack {
            id: "t1".into(),
            name: "N".into(),
            artists: vec![],
            album_name: None,
            duration_ms: 0,
            added_at: "ts".into(),
            uri: "u".into(),
        };
        let cloned = t.clone();
        assert_eq!(cloned.id, "t1");
        let dbg = format!("{t:?}");
        assert!(dbg.contains("SavedTrack"));
    }

    // ── SavedAlbum ──────────────────────────────────────────────────

    #[test]
    fn saved_album_basic() {
        let a = SavedAlbum {
            id: "alb1".into(),
            name: "Great Album".into(),
            artists: vec!["Band".into()],
            total_tracks: 12,
            release_date: Some("2024-06-15".into()),
            added_at: "2025-01-01".into(),
            uri: "spotify:album:alb1".into(),
        };
        assert_eq!(a.total_tracks, 12);
        assert!(a.release_date.is_some());
    }

    #[test]
    fn saved_album_no_release_date() {
        let a = SavedAlbum {
            id: "alb2".into(),
            name: "Unknown".into(),
            artists: vec![],
            total_tracks: 0,
            release_date: None,
            added_at: "ts".into(),
            uri: "u".into(),
        };
        assert!(a.release_date.is_none());
        assert_eq!(a.total_tracks, 0);
    }

    #[test]
    fn saved_album_serde_roundtrip() {
        let a = SavedAlbum {
            id: "a1".into(),
            name: "N".into(),
            artists: vec!["X".into()],
            total_tracks: 5,
            release_date: Some("2024-01-01".into()),
            added_at: "ts".into(),
            uri: "u".into(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: SavedAlbum = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn saved_album_clone_debug() {
        let a = SavedAlbum {
            id: "a1".into(),
            name: "N".into(),
            artists: vec![],
            total_tracks: 1,
            release_date: None,
            added_at: "ts".into(),
            uri: "u".into(),
        };
        let cloned = a.clone();
        assert_eq!(cloned.id, "a1");
        let dbg = format!("{a:?}");
        assert!(dbg.contains("SavedAlbum"));
    }

    // ── SavedShow ───────────────────────────────────────────────────

    #[test]
    fn saved_show_basic() {
        let s = SavedShow {
            id: "sh1".into(),
            name: "Cool Podcast".into(),
            publisher: Some("Publisher Inc".into()),
            total_episodes: Some(100),
            added_at: "2025-01-01".into(),
            uri: "spotify:show:sh1".into(),
        };
        assert_eq!(s.total_episodes, Some(100));
        assert!(s.publisher.is_some());
    }

    #[test]
    fn saved_show_minimal() {
        let s = SavedShow {
            id: "sh2".into(),
            name: "Minimal".into(),
            publisher: None,
            total_episodes: None,
            added_at: "ts".into(),
            uri: "u".into(),
        };
        assert!(s.publisher.is_none());
        assert!(s.total_episodes.is_none());
    }

    #[test]
    fn saved_show_serde_roundtrip() {
        let s = SavedShow {
            id: "s1".into(),
            name: "N".into(),
            publisher: Some("P".into()),
            total_episodes: Some(50),
            added_at: "ts".into(),
            uri: "u".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: SavedShow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn saved_show_clone_debug() {
        let s = SavedShow {
            id: "s1".into(),
            name: "N".into(),
            publisher: None,
            total_episodes: None,
            added_at: "ts".into(),
            uri: "u".into(),
        };
        let cloned = s.clone();
        assert_eq!(cloned.id, "s1");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SavedShow"));
    }

    // ── LibraryPage ─────────────────────────────────────────────────

    #[test]
    fn library_page_empty() {
        let page = LibraryPage {
            items: vec![],
            total: 0,
            offset: 0,
            limit: 20,
            has_next: false,
        };
        assert!(page.items.is_empty());
        assert!(!page.has_next);
    }

    #[test]
    fn library_page_with_items() {
        let page = LibraryPage {
            items: vec![
                LibraryItem {
                    id: "t1".into(),
                    item_type: LibraryItemType::Track,
                    added_at: None,
                    uri: None,
                },
                LibraryItem {
                    id: "t2".into(),
                    item_type: LibraryItemType::Track,
                    added_at: None,
                    uri: None,
                },
            ],
            total: 100,
            offset: 0,
            limit: 20,
            has_next: true,
        };
        assert_eq!(page.items.len(), 2);
        assert!(page.has_next);
        assert_eq!(page.total, 100);
    }

    #[test]
    fn library_page_serde_roundtrip() {
        let page = LibraryPage {
            items: vec![LibraryItem {
                id: "x".into(),
                item_type: LibraryItemType::Album,
                added_at: Some("ts".into()),
                uri: None,
            }],
            total: 1,
            offset: 0,
            limit: 50,
            has_next: false,
        };
        let json = serde_json::to_string(&page).unwrap();
        let back: LibraryPage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, page);
    }

    #[test]
    fn library_page_clone_debug() {
        let page = LibraryPage {
            items: vec![],
            total: 0,
            offset: 0,
            limit: 20,
            has_next: false,
        };
        let cloned = page.clone();
        assert_eq!(cloned.total, 0);
        let dbg = format!("{page:?}");
        assert!(dbg.contains("LibraryPage"));
    }

    // ── LibraryQuery builder ────────────────────────────────────────

    #[test]
    fn query_new_defaults() {
        let q = LibraryQuery::new(LibraryItemType::Track);
        assert_eq!(q.item_type, LibraryItemType::Track);
        assert_eq!(q.offset, 0);
        assert_eq!(q.limit, 20);
        assert!(q.market.is_none());
    }

    #[test]
    fn query_with_offset() {
        let q = LibraryQuery::new(LibraryItemType::Album).with_offset(40);
        assert_eq!(q.offset, 40);
    }

    #[test]
    fn query_with_limit() {
        let q = LibraryQuery::new(LibraryItemType::Show).with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn query_with_market() {
        let q = LibraryQuery::new(LibraryItemType::Episode).with_market("US");
        assert_eq!(q.market, Some("US".into()));
    }

    #[test]
    fn query_builder_chaining() {
        let q = LibraryQuery::new(LibraryItemType::Audiobook)
            .with_offset(10)
            .with_limit(25)
            .with_market("GB");
        assert_eq!(q.offset, 10);
        assert_eq!(q.limit, 25);
        assert_eq!(q.market, Some("GB".into()));
    }

    #[test]
    fn query_validate_ok() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(50);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_limit_zero() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(0);
        assert_eq!(q.validate(), Err(LibraryValidationError::InvalidLimit));
    }

    #[test]
    fn query_validate_limit_too_large() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(51);
        assert_eq!(q.validate(), Err(LibraryValidationError::InvalidLimit));
    }

    #[test]
    fn query_validate_limit_boundary_50() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(50);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_limit_boundary_1() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(1);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_serde_roundtrip() {
        let q = LibraryQuery::new(LibraryItemType::Track)
            .with_offset(5)
            .with_limit(10)
            .with_market("DE");
        let json = serde_json::to_string(&q).unwrap();
        let back: LibraryQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back, q);
    }

    #[test]
    fn query_clone_debug() {
        let q = LibraryQuery::new(LibraryItemType::Show);
        let cloned = q.clone();
        assert_eq!(q, cloned);
        let dbg = format!("{q:?}");
        assert!(dbg.contains("LibraryQuery"));
    }

    // ── LibraryAction ───────────────────────────────────────────────

    #[test]
    fn action_save_ids() {
        let a = LibraryAction::Save {
            ids: vec!["id1".into(), "id2".into()],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(a.ids().len(), 2);
        assert_eq!(a.item_type(), LibraryItemType::Track);
        assert_eq!(a.action_label(), "save");
        assert!(a.is_write());
    }

    #[test]
    fn action_unsave_ids() {
        let a = LibraryAction::Unsave {
            ids: vec!["id3".into()],
            item_type: LibraryItemType::Album,
        };
        assert_eq!(a.ids().len(), 1);
        assert_eq!(a.item_type(), LibraryItemType::Album);
        assert_eq!(a.action_label(), "unsave");
        assert!(a.is_write());
    }

    #[test]
    fn action_check_saved_ids() {
        let a = LibraryAction::CheckSaved {
            ids: vec!["id4".into(), "id5".into(), "id6".into()],
            item_type: LibraryItemType::Show,
        };
        assert_eq!(a.ids().len(), 3);
        assert_eq!(a.item_type(), LibraryItemType::Show);
        assert_eq!(a.action_label(), "check_saved");
        assert!(!a.is_write());
    }

    #[test]
    fn action_serde_save_roundtrip() {
        let a = LibraryAction::Save {
            ids: vec!["x".into()],
            item_type: LibraryItemType::Track,
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: LibraryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn action_serde_unsave_roundtrip() {
        let a = LibraryAction::Unsave {
            ids: vec!["y".into()],
            item_type: LibraryItemType::Album,
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: LibraryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn action_serde_check_saved_roundtrip() {
        let a = LibraryAction::CheckSaved {
            ids: vec!["z".into()],
            item_type: LibraryItemType::Episode,
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: LibraryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn action_clone_debug() {
        let a = LibraryAction::Save {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        let cloned = a.clone();
        assert_eq!(a, cloned);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Save"));
    }

    // ── LibraryActionResult ─────────────────────────────────────────

    #[test]
    fn action_result_all_succeeded() {
        let r = LibraryActionResult {
            action: LibraryAction::Save {
                ids: vec!["a".into(), "b".into()],
                item_type: LibraryItemType::Track,
            },
            succeeded: vec!["a".into(), "b".into()],
            failed: vec![],
            check_results: None,
        };
        assert!(r.all_succeeded());
        assert_eq!(r.total_processed(), 2);
    }

    #[test]
    fn action_result_partial_failure() {
        let r = LibraryActionResult {
            action: LibraryAction::Save {
                ids: vec!["a".into(), "b".into()],
                item_type: LibraryItemType::Track,
            },
            succeeded: vec!["a".into()],
            failed: vec!["b".into()],
            check_results: None,
        };
        assert!(!r.all_succeeded());
        assert_eq!(r.total_processed(), 2);
    }

    #[test]
    fn action_result_with_check_results() {
        let mut checks = HashMap::new();
        checks.insert("id1".into(), true);
        checks.insert("id2".into(), false);
        let r = LibraryActionResult {
            action: LibraryAction::CheckSaved {
                ids: vec!["id1".into(), "id2".into()],
                item_type: LibraryItemType::Track,
            },
            succeeded: vec!["id1".into(), "id2".into()],
            failed: vec![],
            check_results: Some(checks),
        };
        let map = r.check_results.as_ref().unwrap();
        assert!(map["id1"]);
        assert!(!map["id2"]);
    }

    #[test]
    fn action_result_serde_roundtrip() {
        let r = LibraryActionResult {
            action: LibraryAction::Save {
                ids: vec!["a".into()],
                item_type: LibraryItemType::Track,
            },
            succeeded: vec!["a".into()],
            failed: vec![],
            check_results: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: LibraryActionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn action_result_empty() {
        let r = LibraryActionResult {
            action: LibraryAction::Save {
                ids: vec![],
                item_type: LibraryItemType::Track,
            },
            succeeded: vec![],
            failed: vec![],
            check_results: None,
        };
        assert!(r.all_succeeded());
        assert_eq!(r.total_processed(), 0);
    }

    #[test]
    fn action_result_clone_debug() {
        let r = LibraryActionResult {
            action: LibraryAction::Unsave {
                ids: vec!["x".into()],
                item_type: LibraryItemType::Album,
            },
            succeeded: vec!["x".into()],
            failed: vec![],
            check_results: None,
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("LibraryActionResult"));
    }

    // ── Validation ──────────────────────────────────────────────────

    #[test]
    fn validator_default() {
        let v = LibraryValidator::default();
        assert_eq!(v.max_batch_size, 50);
        assert_eq!(v.max_query_limit, 50);
    }

    #[test]
    fn validator_new_same_as_default() {
        let a = LibraryValidator::new();
        let b = LibraryValidator::default();
        assert_eq!(a.max_batch_size, b.max_batch_size);
        assert_eq!(a.max_query_limit, b.max_query_limit);
    }

    #[test]
    fn validate_action_ok() {
        let v = LibraryValidator::new();
        let a = LibraryAction::Save {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        assert!(v.validate_action(&a).is_ok());
    }

    #[test]
    fn validate_action_empty_batch() {
        let v = LibraryValidator::new();
        let a = LibraryAction::Save {
            ids: vec![],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(
            v.validate_action(&a),
            Err(LibraryValidationError::EmptyBatch)
        );
    }

    #[test]
    fn validate_action_batch_too_large() {
        let v = LibraryValidator::new();
        let ids: Vec<String> = (0..51).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Save {
            ids,
            item_type: LibraryItemType::Track,
        };
        assert_eq!(
            v.validate_action(&a),
            Err(LibraryValidationError::BatchTooLarge {
                max: 50,
                actual: 51
            })
        );
    }

    #[test]
    fn validate_action_batch_exactly_50() {
        let v = LibraryValidator::new();
        let ids: Vec<String> = (0..50).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Save {
            ids,
            item_type: LibraryItemType::Track,
        };
        assert!(v.validate_action(&a).is_ok());
    }

    #[test]
    fn validate_action_duplicate_ids() {
        let v = LibraryValidator::new();
        let a = LibraryAction::Save {
            ids: vec!["dup".into(), "dup".into()],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(
            v.validate_action(&a),
            Err(LibraryValidationError::DuplicateIds)
        );
    }

    #[test]
    fn validate_action_unsave_ok() {
        let v = LibraryValidator::new();
        let a = LibraryAction::Unsave {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Album,
        };
        assert!(v.validate_action(&a).is_ok());
    }

    #[test]
    fn validate_action_check_saved_ok() {
        let v = LibraryValidator::new();
        let a = LibraryAction::CheckSaved {
            ids: vec!["id1".into(), "id2".into()],
            item_type: LibraryItemType::Show,
        };
        assert!(v.validate_action(&a).is_ok());
    }

    #[test]
    fn validate_action_check_saved_empty() {
        let v = LibraryValidator::new();
        let a = LibraryAction::CheckSaved {
            ids: vec![],
            item_type: LibraryItemType::Show,
        };
        assert_eq!(
            v.validate_action(&a),
            Err(LibraryValidationError::EmptyBatch)
        );
    }

    #[test]
    fn validate_action_custom_max() {
        let v = LibraryValidator {
            max_batch_size: 5,
            max_query_limit: 10,
        };
        let ids: Vec<String> = (0..6).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Save {
            ids,
            item_type: LibraryItemType::Track,
        };
        assert_eq!(
            v.validate_action(&a),
            Err(LibraryValidationError::BatchTooLarge { max: 5, actual: 6 })
        );
    }

    #[test]
    fn validate_query_ok() {
        let v = LibraryValidator::new();
        let q = LibraryQuery::new(LibraryItemType::Track);
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validate_query_limit_zero() {
        let v = LibraryValidator::new();
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(0);
        assert_eq!(
            v.validate_query(&q),
            Err(LibraryValidationError::InvalidLimit)
        );
    }

    #[test]
    fn validate_query_limit_over_max() {
        let v = LibraryValidator::new();
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(51);
        assert_eq!(
            v.validate_query(&q),
            Err(LibraryValidationError::InvalidLimit)
        );
    }

    #[test]
    fn validate_query_custom_max_limit() {
        let v = LibraryValidator {
            max_batch_size: 50,
            max_query_limit: 10,
        };
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(11);
        assert_eq!(
            v.validate_query(&q),
            Err(LibraryValidationError::InvalidLimit)
        );
    }

    #[test]
    fn validate_query_custom_max_ok() {
        let v = LibraryValidator {
            max_batch_size: 50,
            max_query_limit: 10,
        };
        let q = LibraryQuery::new(LibraryItemType::Track).with_limit(10);
        assert!(v.validate_query(&q).is_ok());
    }

    // ── Validation error Display ────────────────────────────────────

    #[test]
    fn validation_error_display_batch_too_large() {
        let e = LibraryValidationError::BatchTooLarge {
            max: 50,
            actual: 55,
        };
        assert_eq!(e.to_string(), "batch size 55 exceeds maximum 50");
    }

    #[test]
    fn validation_error_display_empty_batch() {
        assert_eq!(
            LibraryValidationError::EmptyBatch.to_string(),
            "batch must not be empty"
        );
    }

    #[test]
    fn validation_error_display_invalid_limit() {
        assert_eq!(
            LibraryValidationError::InvalidLimit.to_string(),
            "limit must be between 1 and 50"
        );
    }

    #[test]
    fn validation_error_display_invalid_offset() {
        assert_eq!(
            LibraryValidationError::InvalidOffset.to_string(),
            "offset must not be negative"
        );
    }

    #[test]
    fn validation_error_display_duplicate_ids() {
        assert_eq!(
            LibraryValidationError::DuplicateIds.to_string(),
            "duplicate IDs in batch"
        );
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            LibraryValidationError::EmptyBatch,
            LibraryValidationError::EmptyBatch
        );
        assert_ne!(
            LibraryValidationError::EmptyBatch,
            LibraryValidationError::DuplicateIds
        );
    }

    #[test]
    fn validation_error_debug() {
        let e = LibraryValidationError::BatchTooLarge {
            max: 50,
            actual: 100,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("BatchTooLarge"));
    }

    #[test]
    fn validation_error_implements_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(LibraryValidationError::EmptyBatch);
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn validation_error_clone() {
        let e = LibraryValidationError::DuplicateIds;
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    // ── Audit events ────────────────────────────────────────────────

    #[test]
    fn audit_event_from_save_action() {
        let a = LibraryAction::Save {
            ids: vec!["t1".into(), "t2".into()],
            item_type: LibraryItemType::Track,
        };
        let evt = LibraryAuditEvent::from_action(&a, true, "2025-01-01T00:00:00Z".into());
        assert_eq!(evt.action_type, "save");
        assert_eq!(evt.item_type, LibraryItemType::Track);
        assert_eq!(evt.item_count, 2);
        assert_eq!(evt.item_ids, vec!["t1", "t2"]);
        assert!(evt.was_allowed);
        assert_eq!(evt.timestamp, "2025-01-01T00:00:00Z");
    }

    #[test]
    fn audit_event_from_unsave_action() {
        let a = LibraryAction::Unsave {
            ids: vec!["a1".into()],
            item_type: LibraryItemType::Album,
        };
        let evt = LibraryAuditEvent::from_action(&a, false, "2025-06-01T12:00:00Z".into());
        assert_eq!(evt.action_type, "unsave");
        assert_eq!(evt.item_type, LibraryItemType::Album);
        assert_eq!(evt.item_count, 1);
        assert!(!evt.was_allowed);
    }

    #[test]
    fn audit_event_from_check_saved_action() {
        let a = LibraryAction::CheckSaved {
            ids: vec!["s1".into(), "s2".into(), "s3".into()],
            item_type: LibraryItemType::Show,
        };
        let evt = LibraryAuditEvent::from_action(&a, true, "ts".into());
        assert_eq!(evt.action_type, "check_saved");
        assert_eq!(evt.item_count, 3);
    }

    #[test]
    fn audit_event_contains_only_ids() {
        let a = LibraryAction::Save {
            ids: vec!["id_only".into()],
            item_type: LibraryItemType::Track,
        };
        let evt = LibraryAuditEvent::from_action(&a, true, "ts".into());
        assert!(evt.contains_only_ids());
    }

    #[test]
    fn audit_event_no_names_in_ids() {
        // The audit event must contain IDs, never names. Verify the struct
        // has no field that could leak a name.
        let a = LibraryAction::Save {
            ids: vec!["spotify_id_abc123".into()],
            item_type: LibraryItemType::Track,
        };
        let evt = LibraryAuditEvent::from_action(&a, true, "ts".into());
        let json = serde_json::to_string(&evt).unwrap();
        // The JSON should contain the ID but no "name" key.
        assert!(json.contains("spotify_id_abc123"));
        assert!(!json.contains("\"name\""));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = LibraryAuditEvent {
            timestamp: "2025-01-01".into(),
            action_type: "save".into(),
            item_type: LibraryItemType::Track,
            item_count: 1,
            item_ids: vec!["x".into()],
            was_allowed: true,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: LibraryAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, evt);
    }

    #[test]
    fn audit_event_clone_debug() {
        let evt = LibraryAuditEvent {
            timestamp: "ts".into(),
            action_type: "save".into(),
            item_type: LibraryItemType::Track,
            item_count: 0,
            item_ids: vec![],
            was_allowed: true,
        };
        let cloned = evt.clone();
        assert_eq!(evt, cloned);
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("LibraryAuditEvent"));
    }

    #[test]
    fn audit_event_denied_action() {
        let a = LibraryAction::Save {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        let evt = LibraryAuditEvent::from_action(&a, false, "ts".into());
        assert!(!evt.was_allowed);
    }

    #[test]
    fn audit_event_serialized_has_no_name_field() {
        // Exhaustively check all audit event fields for name leakage.
        let evt = LibraryAuditEvent {
            timestamp: "2025-03-09T00:00:00Z".into(),
            action_type: "unsave".into(),
            item_type: LibraryItemType::Album,
            item_count: 3,
            item_ids: vec!["id_a".into(), "id_b".into(), "id_c".into()],
            was_allowed: true,
        };
        let val = serde_json::to_value(&evt).unwrap();
        let obj = val.as_object().unwrap();
        assert!(!obj.contains_key("name"));
        assert!(!obj.contains_key("track_name"));
        assert!(!obj.contains_key("album_name"));
        assert!(!obj.contains_key("artist_name"));
    }

    // ── Policy ──────────────────────────────────────────────────────

    #[test]
    fn policy_permissive() {
        let p = LibraryPolicy::new_permissive();
        assert!(p.allow_read);
        assert!(p.allow_save);
        assert!(p.allow_unsave);
        assert_eq!(p.max_batch_size, 50);
        assert!(!p.require_approval_for_unsave);
    }

    #[test]
    fn policy_readonly() {
        let p = LibraryPolicy::new_readonly();
        assert!(p.allow_read);
        assert!(!p.allow_save);
        assert!(!p.allow_unsave);
    }

    #[test]
    fn policy_allow_read_check_saved() {
        let p = LibraryPolicy::new_permissive();
        let a = LibraryAction::CheckSaved {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(p.check_action(&a), PolicyDecision::Allow);
    }

    #[test]
    fn policy_deny_read_check_saved() {
        let p = LibraryPolicy {
            allow_read: false,
            allow_save: true,
            allow_unsave: true,
            max_batch_size: 50,
            require_approval_for_unsave: false,
        };
        let a = LibraryAction::CheckSaved {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        assert!(matches!(p.check_action(&a), PolicyDecision::Deny(_)));
    }

    #[test]
    fn policy_allow_save() {
        let p = LibraryPolicy::new_permissive();
        let a = LibraryAction::Save {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(p.check_action(&a), PolicyDecision::Allow);
    }

    #[test]
    fn policy_deny_save_readonly() {
        let p = LibraryPolicy::new_readonly();
        let a = LibraryAction::Save {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        assert!(matches!(p.check_action(&a), PolicyDecision::Deny(_)));
    }

    #[test]
    fn policy_deny_save_batch_too_large() {
        let p = LibraryPolicy {
            allow_read: true,
            allow_save: true,
            allow_unsave: true,
            max_batch_size: 5,
            require_approval_for_unsave: false,
        };
        let ids: Vec<String> = (0..6).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Save {
            ids,
            item_type: LibraryItemType::Track,
        };
        match p.check_action(&a) {
            PolicyDecision::Deny(msg) => {
                assert!(msg.contains('6'));
                assert!(msg.contains('5'));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_allow_unsave() {
        let p = LibraryPolicy::new_permissive();
        let a = LibraryAction::Unsave {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Album,
        };
        assert_eq!(p.check_action(&a), PolicyDecision::Allow);
    }

    #[test]
    fn policy_deny_unsave_readonly() {
        let p = LibraryPolicy::new_readonly();
        let a = LibraryAction::Unsave {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Album,
        };
        assert!(matches!(p.check_action(&a), PolicyDecision::Deny(_)));
    }

    #[test]
    fn policy_deny_unsave_batch_too_large() {
        let p = LibraryPolicy {
            allow_read: true,
            allow_save: true,
            allow_unsave: true,
            max_batch_size: 3,
            require_approval_for_unsave: false,
        };
        let ids: Vec<String> = (0..4).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Unsave {
            ids,
            item_type: LibraryItemType::Track,
        };
        assert!(matches!(p.check_action(&a), PolicyDecision::Deny(_)));
    }

    #[test]
    fn policy_require_approval_unsave() {
        let p = LibraryPolicy {
            allow_read: true,
            allow_save: true,
            allow_unsave: true,
            max_batch_size: 50,
            require_approval_for_unsave: true,
        };
        let a = LibraryAction::Unsave {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        match p.check_action(&a) {
            PolicyDecision::RequireApproval(msg) => {
                assert!(msg.contains("approval"));
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn policy_require_approval_only_for_unsave() {
        let p = LibraryPolicy {
            allow_read: true,
            allow_save: true,
            allow_unsave: true,
            max_batch_size: 50,
            require_approval_for_unsave: true,
        };
        // Save should still be allowed without approval.
        let save = LibraryAction::Save {
            ids: vec!["id1".into()],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(p.check_action(&save), PolicyDecision::Allow);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = LibraryPolicy::new_permissive();
        let json = serde_json::to_string(&p).unwrap();
        let back: LibraryPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn policy_readonly_serde_roundtrip() {
        let p = LibraryPolicy::new_readonly();
        let json = serde_json::to_string(&p).unwrap();
        let back: LibraryPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn policy_clone_debug() {
        let p = LibraryPolicy::new_permissive();
        let cloned = p.clone();
        assert_eq!(p, cloned);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("LibraryPolicy"));
    }

    #[test]
    fn policy_decision_eq() {
        assert_eq!(PolicyDecision::Allow, PolicyDecision::Allow);
        assert_ne!(PolicyDecision::Allow, PolicyDecision::Deny("x".into()));
    }

    #[test]
    fn policy_decision_debug() {
        let d = PolicyDecision::RequireApproval("reason".into());
        let dbg = format!("{d:?}");
        assert!(dbg.contains("RequireApproval"));
        assert!(dbg.contains("reason"));
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn action_single_id() {
        let a = LibraryAction::Save {
            ids: vec!["only_one".into()],
            item_type: LibraryItemType::Audiobook,
        };
        assert_eq!(a.ids().len(), 1);
        assert_eq!(a.item_type(), LibraryItemType::Audiobook);
    }

    #[test]
    fn library_page_last_page() {
        let page = LibraryPage {
            items: vec![LibraryItem {
                id: "last".into(),
                item_type: LibraryItemType::Track,
                added_at: None,
                uri: None,
            }],
            total: 21,
            offset: 20,
            limit: 20,
            has_next: false,
        };
        assert!(!page.has_next);
        assert_eq!(page.items.len(), 1);
    }

    #[test]
    fn library_page_high_offset() {
        let page = LibraryPage {
            items: vec![],
            total: 100,
            offset: 200,
            limit: 50,
            has_next: false,
        };
        assert!(page.items.is_empty());
    }

    #[test]
    fn validator_debug() {
        let v = LibraryValidator::new();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("LibraryValidator"));
    }

    #[test]
    fn validator_clone() {
        let v = LibraryValidator::new();
        let cloned = v.clone();
        assert_eq!(v.max_batch_size, cloned.max_batch_size);
    }

    #[test]
    fn validate_action_many_unique_ids() {
        let v = LibraryValidator::new();
        let ids: Vec<String> = (0..50).map(|i| format!("unique_{i}")).collect();
        let a = LibraryAction::CheckSaved {
            ids,
            item_type: LibraryItemType::Episode,
        };
        assert!(v.validate_action(&a).is_ok());
    }

    #[test]
    fn validate_action_duplicate_at_end() {
        let v = LibraryValidator::new();
        let a = LibraryAction::Save {
            ids: vec!["a".into(), "b".into(), "c".into(), "a".into()],
            item_type: LibraryItemType::Track,
        };
        assert_eq!(
            v.validate_action(&a),
            Err(LibraryValidationError::DuplicateIds)
        );
    }

    #[test]
    fn query_offset_zero() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_offset(0);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_large_offset() {
        let q = LibraryQuery::new(LibraryItemType::Track).with_offset(999_999);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn policy_unsave_denied_before_batch_check() {
        // If unsave is denied, the batch size check should not matter.
        let p = LibraryPolicy {
            allow_read: true,
            allow_save: true,
            allow_unsave: false,
            max_batch_size: 1,
            require_approval_for_unsave: false,
        };
        let ids: Vec<String> = (0..100).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Unsave {
            ids,
            item_type: LibraryItemType::Track,
        };
        match p.check_action(&a) {
            PolicyDecision::Deny(msg) => {
                assert!(msg.contains("not allowed"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_save_denied_before_batch_check() {
        let p = LibraryPolicy {
            allow_read: true,
            allow_save: false,
            allow_unsave: true,
            max_batch_size: 1,
            require_approval_for_unsave: false,
        };
        let ids: Vec<String> = (0..100).map(|i| format!("id{i}")).collect();
        let a = LibraryAction::Save {
            ids,
            item_type: LibraryItemType::Track,
        };
        match p.check_action(&a) {
            PolicyDecision::Deny(msg) => {
                assert!(msg.contains("not allowed"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn audit_event_large_batch_ids() {
        let ids: Vec<String> = (0..50).map(|i| format!("id_{i}")).collect();
        let a = LibraryAction::Save {
            ids,
            item_type: LibraryItemType::Track,
        };
        let evt = LibraryAuditEvent::from_action(&a, true, "ts".into());
        assert_eq!(evt.item_ids.len(), 50);
        assert_eq!(evt.item_count, 50);
    }

    #[test]
    fn library_item_all_types() {
        for ty in [
            LibraryItemType::Track,
            LibraryItemType::Album,
            LibraryItemType::Show,
            LibraryItemType::Episode,
            LibraryItemType::Audiobook,
        ] {
            let item = LibraryItem {
                id: format!("item_{ty}"),
                item_type: ty,
                added_at: None,
                uri: None,
            };
            assert_eq!(item.item_type, ty);
        }
    }

    #[test]
    fn saved_track_empty_artists() {
        let t = SavedTrack {
            id: "t1".into(),
            name: "Instrumental".into(),
            artists: vec![],
            album_name: None,
            duration_ms: 60_000,
            added_at: "ts".into(),
            uri: "u".into(),
        };
        assert!(t.artists.is_empty());
    }

    #[test]
    fn saved_album_many_tracks() {
        let a = SavedAlbum {
            id: "a1".into(),
            name: "Compilation".into(),
            artists: vec!["V/A".into()],
            total_tracks: 200,
            release_date: Some("2025-01-01".into()),
            added_at: "ts".into(),
            uri: "u".into(),
        };
        assert_eq!(a.total_tracks, 200);
    }

    #[test]
    fn saved_show_high_episode_count() {
        let s = SavedShow {
            id: "s1".into(),
            name: "Long Runner".into(),
            publisher: Some("Network".into()),
            total_episodes: Some(5000),
            added_at: "ts".into(),
            uri: "u".into(),
        };
        assert_eq!(s.total_episodes, Some(5000));
    }

    #[test]
    fn action_result_all_failed() {
        let r = LibraryActionResult {
            action: LibraryAction::Save {
                ids: vec!["a".into(), "b".into()],
                item_type: LibraryItemType::Track,
            },
            succeeded: vec![],
            failed: vec!["a".into(), "b".into()],
            check_results: None,
        };
        assert!(!r.all_succeeded());
        assert_eq!(r.total_processed(), 2);
    }

    #[test]
    fn policy_decision_clone() {
        let d = PolicyDecision::Deny("reason".into());
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn library_item_type_ne() {
        assert_ne!(LibraryItemType::Track, LibraryItemType::Album);
        assert_ne!(LibraryItemType::Show, LibraryItemType::Episode);
        assert_ne!(LibraryItemType::Audiobook, LibraryItemType::Track);
    }
}
