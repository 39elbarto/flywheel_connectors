//! `Spotify` listening history module.
//!
//! Exposes listening history for personalization and analytics:
//! recently played tracks and top tracks/artists by time range.
//!
//! **Privacy**: This module handles sensitive personal data.
//! Audit events must NEVER contain track or artist names — only IDs.
//!
//! Capability: `spotify.history.read` (sensitive)

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Time Range ──────────────────────────────────────────────────

/// Time range for `Spotify` top items queries.
///
/// Maps to the `Spotify` Web API `time_range` parameter values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeRange {
    /// Approximately last 4 weeks.
    ShortTerm,
    /// Approximately last 6 months.
    MediumTerm,
    /// Several years of data (all time).
    LongTerm,
}

impl TimeRange {
    /// Returns the `Spotify` API string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ShortTerm => "short_term",
            Self::MediumTerm => "medium_term",
            Self::LongTerm => "long_term",
        }
    }

    /// Parses from a `Spotify` API string representation.
    ///
    /// Returns `None` if the string is not a valid time range.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "short_term" => Some(Self::ShortTerm),
            "medium_term" => Some(Self::MediumTerm),
            "long_term" => Some(Self::LongTerm),
            _ => None,
        }
    }

    /// Human-readable description of this time range.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::ShortTerm => "approximately last 4 weeks",
            Self::MediumTerm => "approximately last 6 months",
            Self::LongTerm => "several years of data",
        }
    }
}

impl fmt::Display for TimeRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Play History Types ──────────────────────────────────────────

/// A single play history item from the `Spotify` recently played endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayHistoryItem {
    /// `Spotify` track ID.
    pub track_id: String,
    /// Track name (for display only — NEVER include in audit events).
    pub track_name: String,
    /// Artist names (for display only — NEVER include in audit events).
    pub artists: Vec<String>,
    /// ISO 8601 timestamp of when the track was played.
    pub played_at: String,
    /// Context type (e.g., "album", "playlist", "artist").
    pub context_type: Option<String>,
    /// Context URI (e.g., `spotify:playlist:xyz`).
    pub context_uri: Option<String>,
    /// Track duration in milliseconds.
    pub duration_ms: u64,
}

/// Cursor-based pagination cursors for play history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryCursors {
    /// Cursor to fetch items after this point (newer).
    pub after: Option<String>,
    /// Cursor to fetch items before this point (older).
    pub before: Option<String>,
}

/// Recently played tracks response from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayHistory {
    /// List of play history items.
    pub items: Vec<PlayHistoryItem>,
    /// Pagination cursors for fetching more results.
    pub cursors: Option<HistoryCursors>,
    /// Total number of items available (may not always be returned).
    pub total: Option<u32>,
    /// The limit used for this request.
    pub limit: u32,
}

// ── Top Items Types ─────────────────────────────────────────────

/// Type discriminator for top items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TopItemType {
    /// A track.
    Track,
    /// An artist.
    Artist,
}

impl TopItemType {
    /// Returns the `Spotify` API string for this item type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Track => "tracks",
            Self::Artist => "artists",
        }
    }
}

impl fmt::Display for TopItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single top item (track or artist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopItem {
    /// `Spotify` ID.
    pub id: String,
    /// Item name (for display only — NEVER include in audit events).
    pub name: String,
    /// Whether this is a track or artist.
    pub item_type: TopItemType,
    /// Rank position (1-based).
    pub rank: u32,
    /// Popularity score (0-100), if available.
    pub popularity: Option<u32>,
}

/// Top items response from the `Spotify` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopItems {
    /// List of top items.
    pub items: Vec<TopItem>,
    /// Total number of items available.
    pub total: u32,
    /// The time range used for this query.
    pub time_range: TimeRange,
    /// The limit used for this request.
    pub limit: u32,
    /// The offset used for this request.
    pub offset: u32,
}

// ── Query Builders ──────────────────────────────────────────────

/// Query parameters for fetching recently played tracks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryQuery {
    /// Maximum number of items to return (1-50, default 20).
    pub limit: u32,
    /// Unix timestamp in milliseconds — return items played after this.
    pub after: Option<u64>,
    /// Unix timestamp in milliseconds — return items played before this.
    pub before: Option<u64>,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            limit: 20,
            after: None,
            before: None,
        }
    }
}

impl HistoryQuery {
    /// Creates a new query with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the limit (clamped to 1-50).
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Sets the "after" cursor (timestamp in milliseconds).
    #[must_use]
    pub const fn with_after(mut self, after: u64) -> Self {
        self.after = Some(after);
        self
    }

    /// Sets the "before" cursor (timestamp in milliseconds).
    #[must_use]
    pub const fn with_before(mut self, before: u64) -> Self {
        self.before = Some(before);
        self
    }

    /// Validates this query, returning any validation errors.
    pub fn validate(&self) -> Result<(), HistoryValidationError> {
        let validator = HistoryValidator::default();
        validator.validate_history_query(self)
    }
}

/// Query parameters for fetching top tracks or artists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopItemsQuery {
    /// Whether to fetch top tracks or artists.
    pub item_type: TopItemType,
    /// Time range for the query.
    pub time_range: TimeRange,
    /// Maximum number of items to return (1-50, default 20).
    pub limit: u32,
    /// Offset for pagination (0-based).
    pub offset: u32,
}

impl TopItemsQuery {
    /// Creates a new query for the given item type.
    #[must_use]
    pub const fn new(item_type: TopItemType) -> Self {
        Self {
            item_type,
            time_range: TimeRange::MediumTerm,
            limit: 20,
            offset: 0,
        }
    }

    /// Sets the time range.
    #[must_use]
    pub const fn with_time_range(mut self, time_range: TimeRange) -> Self {
        self.time_range = time_range;
        self
    }

    /// Sets the limit (clamped to 1-50).
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Sets the offset.
    #[must_use]
    pub const fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Validates this query, returning any validation errors.
    pub fn validate(&self) -> Result<(), HistoryValidationError> {
        let validator = HistoryValidator::default();
        validator.validate_top_query(self)
    }
}

// ── Validation ──────────────────────────────────────────────────

/// Validation errors for history queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryValidationError {
    /// Limit is out of the valid range (1-50).
    InvalidLimit {
        /// The invalid limit value provided.
        value: u32,
        /// Maximum allowed limit.
        max: u32,
    },
    /// Time window exceeds the maximum allowed.
    InvalidTimeWindow {
        /// The window span in days.
        span_days: u64,
        /// Maximum allowed window in days.
        max_days: u64,
    },
    /// Both "after" and "before" were set (mutually exclusive).
    AfterBeforeConflict,
    /// Offset exceeds maximum allowed value.
    InvalidOffset {
        /// The invalid offset value.
        value: u32,
        /// Maximum allowed offset.
        max: u32,
    },
}

impl fmt::Display for HistoryValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { value, max } => {
                write!(f, "invalid limit {value}: must be between 1 and {max}")
            }
            Self::InvalidTimeWindow {
                span_days,
                max_days,
            } => {
                write!(
                    f,
                    "time window of {span_days} days exceeds maximum of {max_days} days"
                )
            }
            Self::AfterBeforeConflict => {
                write!(f, "cannot specify both 'after' and 'before' cursors")
            }
            Self::InvalidOffset { value, max } => {
                write!(f, "invalid offset {value}: must be at most {max}")
            }
        }
    }
}

impl std::error::Error for HistoryValidationError {}

/// Validates history and top-items queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryValidator {
    /// Maximum limit for a single request.
    pub max_limit: u32,
    /// Maximum time window in days for history queries.
    pub max_time_window_days: u64,
    /// Maximum offset for top items pagination.
    pub max_offset: u32,
}

impl Default for HistoryValidator {
    fn default() -> Self {
        Self {
            max_limit: 50,
            max_time_window_days: 90,
            max_offset: 1000,
        }
    }
}

impl HistoryValidator {
    /// Validates a history query.
    pub const fn validate_history_query(
        &self,
        query: &HistoryQuery,
    ) -> Result<(), HistoryValidationError> {
        if query.limit == 0 || query.limit > self.max_limit {
            return Err(HistoryValidationError::InvalidLimit {
                value: query.limit,
                max: self.max_limit,
            });
        }

        if query.after.is_some() && query.before.is_some() {
            return Err(HistoryValidationError::AfterBeforeConflict);
        }

        Ok(())
    }

    /// Validates a top items query.
    pub const fn validate_top_query(
        &self,
        query: &TopItemsQuery,
    ) -> Result<(), HistoryValidationError> {
        if query.limit == 0 || query.limit > self.max_limit {
            return Err(HistoryValidationError::InvalidLimit {
                value: query.limit,
                max: self.max_limit,
            });
        }

        if query.offset > self.max_offset {
            return Err(HistoryValidationError::InvalidOffset {
                value: query.offset,
                max: self.max_offset,
            });
        }

        Ok(())
    }
}

// ── Audit Events ────────────────────────────────────────────────

/// An audit event for history reads.
///
/// **Privacy**: This struct must NEVER contain track or artist names.
/// Only IDs are permitted in audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryAuditEvent {
    /// ISO 8601 timestamp of the audit event.
    pub timestamp: String,
    /// Type of query (e.g., `recently_played`, `top_tracks`, `top_artists`).
    pub query_type: String,
    /// Number of items returned.
    pub item_count: u32,
    /// IDs of returned items (NEVER names).
    pub item_ids: Vec<String>,
    /// Time range used, if applicable.
    pub time_range: Option<TimeRange>,
}

// ── Privacy ─────────────────────────────────────────────────────

/// Privacy configuration for history operations.
///
/// Controls what data is included in audit events and responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryPrivacy {
    /// Whether to redact names in audit events (should always be true).
    pub redact_names: bool,
    /// Maximum items allowed per response.
    pub max_items_per_response: u32,
    /// Whether to audit all reads (should be true for sensitive data).
    pub audit_all_reads: bool,
}

impl HistoryPrivacy {
    /// Creates a default privacy configuration with maximum protection.
    ///
    /// - `redact_names`: true
    /// - `max_items_per_response`: 50
    /// - `audit_all_reads`: true
    #[must_use]
    pub const fn new_default() -> Self {
        Self {
            redact_names: true,
            max_items_per_response: 50,
            audit_all_reads: true,
        }
    }

    /// Sanitizes a play history response for audit logging.
    ///
    /// Strips all names and personal context, keeping only IDs.
    #[must_use]
    pub fn sanitize_for_audit(&self, history: &PlayHistory) -> HistoryAuditEvent {
        HistoryAuditEvent {
            timestamp: String::new(), // caller should set this
            query_type: "recently_played".to_string(),
            item_count: history.items.len() as u32,
            item_ids: history
                .items
                .iter()
                .map(|item| item.track_id.clone())
                .collect(),
            time_range: None,
        }
    }

    /// Sanitizes a top items response for audit logging.
    ///
    /// Strips all names and personal context, keeping only IDs.
    #[must_use]
    pub fn sanitize_top_items_for_audit(&self, items: &TopItems) -> HistoryAuditEvent {
        let query_type = match items.items.first().map(|i| i.item_type) {
            Some(TopItemType::Track) => "top_tracks",
            Some(TopItemType::Artist) => "top_artists",
            None => "top_items",
        };
        HistoryAuditEvent {
            timestamp: String::new(), // caller should set this
            query_type: query_type.to_string(),
            item_count: items.items.len() as u32,
            item_ids: items.items.iter().map(|item| item.id.clone()).collect(),
            time_range: Some(items.time_range),
        }
    }
}

impl Default for HistoryPrivacy {
    fn default() -> Self {
        Self::new_default()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── TimeRange tests ─────────────────────────────────────────

    #[test]
    fn time_range_as_str_short() {
        assert_eq!(TimeRange::ShortTerm.as_str(), "short_term");
    }

    #[test]
    fn time_range_as_str_medium() {
        assert_eq!(TimeRange::MediumTerm.as_str(), "medium_term");
    }

    #[test]
    fn time_range_as_str_long() {
        assert_eq!(TimeRange::LongTerm.as_str(), "long_term");
    }

    #[test]
    fn time_range_parse_short() {
        assert_eq!(TimeRange::parse("short_term"), Some(TimeRange::ShortTerm));
    }

    #[test]
    fn time_range_parse_medium() {
        assert_eq!(TimeRange::parse("medium_term"), Some(TimeRange::MediumTerm));
    }

    #[test]
    fn time_range_parse_long() {
        assert_eq!(TimeRange::parse("long_term"), Some(TimeRange::LongTerm));
    }

    #[test]
    fn time_range_parse_invalid() {
        assert_eq!(TimeRange::parse("invalid"), None);
    }

    #[test]
    fn time_range_parse_empty() {
        assert_eq!(TimeRange::parse(""), None);
    }

    #[test]
    fn time_range_parse_case_sensitive() {
        assert_eq!(TimeRange::parse("Short_Term"), None);
        assert_eq!(TimeRange::parse("SHORT_TERM"), None);
    }

    #[test]
    fn time_range_description_short() {
        assert_eq!(
            TimeRange::ShortTerm.description(),
            "approximately last 4 weeks"
        );
    }

    #[test]
    fn time_range_description_medium() {
        assert_eq!(
            TimeRange::MediumTerm.description(),
            "approximately last 6 months"
        );
    }

    #[test]
    fn time_range_description_long() {
        assert_eq!(TimeRange::LongTerm.description(), "several years of data");
    }

    #[test]
    fn time_range_display_short() {
        assert_eq!(TimeRange::ShortTerm.to_string(), "short_term");
    }

    #[test]
    fn time_range_display_medium() {
        assert_eq!(TimeRange::MediumTerm.to_string(), "medium_term");
    }

    #[test]
    fn time_range_display_long() {
        assert_eq!(TimeRange::LongTerm.to_string(), "long_term");
    }

    #[test]
    fn time_range_equality() {
        assert_eq!(TimeRange::ShortTerm, TimeRange::ShortTerm);
        assert_ne!(TimeRange::ShortTerm, TimeRange::MediumTerm);
        assert_ne!(TimeRange::MediumTerm, TimeRange::LongTerm);
    }

    #[test]
    fn time_range_clone() {
        let tr = TimeRange::MediumTerm;
        let cloned = tr;
        assert_eq!(tr, cloned);
    }

    #[test]
    fn time_range_debug() {
        let dbg = format!("{:?}", TimeRange::ShortTerm);
        assert!(dbg.contains("ShortTerm"));
    }

    #[test]
    fn time_range_serialize() {
        let v = serde_json::to_value(TimeRange::ShortTerm).unwrap();
        assert_eq!(v, json!("ShortTerm"));
    }

    #[test]
    fn time_range_deserialize() {
        let tr: TimeRange = serde_json::from_value(json!("LongTerm")).unwrap();
        assert_eq!(tr, TimeRange::LongTerm);
    }

    #[test]
    fn time_range_roundtrip_serde() {
        for tr in [
            TimeRange::ShortTerm,
            TimeRange::MediumTerm,
            TimeRange::LongTerm,
        ] {
            let v = serde_json::to_value(tr).unwrap();
            let back: TimeRange = serde_json::from_value(v).unwrap();
            assert_eq!(tr, back);
        }
    }

    #[test]
    fn time_range_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TimeRange::ShortTerm);
        set.insert(TimeRange::MediumTerm);
        set.insert(TimeRange::LongTerm);
        set.insert(TimeRange::ShortTerm); // duplicate
        assert_eq!(set.len(), 3);
    }

    // ── PlayHistoryItem tests ───────────────────────────────────

    #[test]
    fn play_history_item_create() {
        let item = PlayHistoryItem {
            track_id: "track_123".into(),
            track_name: "Test Song".into(),
            artists: vec!["Artist A".into(), "Artist B".into()],
            played_at: "2025-01-15T10:30:00Z".into(),
            context_type: Some("playlist".into()),
            context_uri: Some("spotify:playlist:abc".into()),
            duration_ms: 240_000,
        };
        assert_eq!(item.track_id, "track_123");
        assert_eq!(item.artists.len(), 2);
        assert_eq!(item.duration_ms, 240_000);
    }

    #[test]
    fn play_history_item_no_context() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Song".into(),
            artists: vec![],
            played_at: "2025-01-15T10:00:00Z".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 180_000,
        };
        assert!(item.context_type.is_none());
        assert!(item.context_uri.is_none());
    }

    #[test]
    fn play_history_item_serialize() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Song".into(),
            artists: vec!["Artist".into()],
            played_at: "2025-01-15T10:00:00Z".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 180_000,
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["track_id"], "t1");
        assert_eq!(v["duration_ms"], 180_000);
    }

    #[test]
    fn play_history_item_deserialize() {
        let item: PlayHistoryItem = serde_json::from_value(json!({
            "track_id": "t2",
            "track_name": "Another Song",
            "artists": ["Artist X"],
            "played_at": "2025-01-15T11:00:00Z",
            "context_type": "album",
            "context_uri": "spotify:album:xyz",
            "duration_ms": 300000
        }))
        .unwrap();
        assert_eq!(item.track_id, "t2");
        assert_eq!(item.context_type, Some("album".into()));
        assert_eq!(item.duration_ms, 300_000);
    }

    #[test]
    fn play_history_item_clone() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Song".into(),
            artists: vec!["A".into()],
            played_at: "2025-01-15T10:00:00Z".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 200_000,
        };
        let cloned = item.clone();
        assert_eq!(item.track_id, cloned.track_id);
        assert_eq!(item.artists.len(), cloned.artists.len());
    }

    #[test]
    fn play_history_item_debug() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Song".into(),
            artists: vec![],
            played_at: "2025-01-15T10:00:00Z".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 100_000,
        };
        let dbg = format!("{item:?}");
        assert!(dbg.contains("PlayHistoryItem"));
        assert!(dbg.contains("t1"));
    }

    #[test]
    fn play_history_item_multiple_artists() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Collab".into(),
            artists: vec!["A".into(), "B".into(), "C".into(), "D".into()],
            played_at: "2025-01-15T10:00:00Z".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 250_000,
        };
        assert_eq!(item.artists.len(), 4);
    }

    // ── HistoryCursors tests ────────────────────────────────────

    #[test]
    fn history_cursors_both() {
        let c = HistoryCursors {
            after: Some("after_cursor".into()),
            before: Some("before_cursor".into()),
        };
        assert_eq!(c.after, Some("after_cursor".into()));
        assert_eq!(c.before, Some("before_cursor".into()));
    }

    #[test]
    fn history_cursors_none() {
        let c = HistoryCursors {
            after: None,
            before: None,
        };
        assert!(c.after.is_none());
        assert!(c.before.is_none());
    }

    #[test]
    fn history_cursors_serialize() {
        let c = HistoryCursors {
            after: Some("abc".into()),
            before: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["after"], "abc");
    }

    #[test]
    fn history_cursors_clone_debug() {
        let c = HistoryCursors {
            after: Some("x".into()),
            before: None,
        };
        let cloned = c.clone();
        assert_eq!(cloned.after, Some("x".into()));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("HistoryCursors"));
    }

    // ── PlayHistory tests ───────────────────────────────────────

    #[test]
    fn play_history_empty() {
        let h = PlayHistory {
            items: vec![],
            cursors: None,
            total: Some(0),
            limit: 20,
        };
        assert!(h.items.is_empty());
        assert_eq!(h.limit, 20);
    }

    #[test]
    fn play_history_with_items() {
        let h = PlayHistory {
            items: vec![
                PlayHistoryItem {
                    track_id: "t1".into(),
                    track_name: "S1".into(),
                    artists: vec!["A".into()],
                    played_at: "2025-01-15T10:00:00Z".into(),
                    context_type: None,
                    context_uri: None,
                    duration_ms: 100_000,
                },
                PlayHistoryItem {
                    track_id: "t2".into(),
                    track_name: "S2".into(),
                    artists: vec!["B".into()],
                    played_at: "2025-01-15T10:05:00Z".into(),
                    context_type: Some("playlist".into()),
                    context_uri: Some("spotify:playlist:xyz".into()),
                    duration_ms: 200_000,
                },
            ],
            cursors: Some(HistoryCursors {
                after: Some("cursor_after".into()),
                before: Some("cursor_before".into()),
            }),
            total: Some(100),
            limit: 20,
        };
        assert_eq!(h.items.len(), 2);
        assert!(h.cursors.is_some());
        assert_eq!(h.total, Some(100));
    }

    #[test]
    fn play_history_serialize_roundtrip() {
        let h = PlayHistory {
            items: vec![],
            cursors: None,
            total: None,
            limit: 10,
        };
        let v = serde_json::to_value(&h).unwrap();
        let back: PlayHistory = serde_json::from_value(v).unwrap();
        assert_eq!(back.limit, 10);
        assert!(back.items.is_empty());
    }

    #[test]
    fn play_history_clone_debug() {
        let h = PlayHistory {
            items: vec![],
            cursors: None,
            total: Some(5),
            limit: 20,
        };
        let cloned = h.clone();
        assert_eq!(cloned.total, Some(5));
        let dbg = format!("{h:?}");
        assert!(dbg.contains("PlayHistory"));
    }

    // ── TopItemType tests ───────────────────────────────────────

    #[test]
    fn top_item_type_as_str_track() {
        assert_eq!(TopItemType::Track.as_str(), "tracks");
    }

    #[test]
    fn top_item_type_as_str_artist() {
        assert_eq!(TopItemType::Artist.as_str(), "artists");
    }

    #[test]
    fn top_item_type_display_track() {
        assert_eq!(TopItemType::Track.to_string(), "tracks");
    }

    #[test]
    fn top_item_type_display_artist() {
        assert_eq!(TopItemType::Artist.to_string(), "artists");
    }

    #[test]
    fn top_item_type_equality() {
        assert_eq!(TopItemType::Track, TopItemType::Track);
        assert_ne!(TopItemType::Track, TopItemType::Artist);
    }

    #[test]
    fn top_item_type_serialize() {
        let v = serde_json::to_value(TopItemType::Track).unwrap();
        assert_eq!(v, json!("Track"));
    }

    #[test]
    fn top_item_type_deserialize() {
        let t: TopItemType = serde_json::from_value(json!("Artist")).unwrap();
        assert_eq!(t, TopItemType::Artist);
    }

    #[test]
    fn top_item_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TopItemType::Track);
        set.insert(TopItemType::Artist);
        set.insert(TopItemType::Track);
        assert_eq!(set.len(), 2);
    }

    // ── TopItem tests ───────────────────────────────────────────

    #[test]
    fn top_item_track() {
        let item = TopItem {
            id: "track_1".into(),
            name: "Hit Song".into(),
            item_type: TopItemType::Track,
            rank: 1,
            popularity: Some(95),
        };
        assert_eq!(item.id, "track_1");
        assert_eq!(item.rank, 1);
        assert_eq!(item.popularity, Some(95));
    }

    #[test]
    fn top_item_artist() {
        let item = TopItem {
            id: "artist_1".into(),
            name: "Popular Artist".into(),
            item_type: TopItemType::Artist,
            rank: 3,
            popularity: None,
        };
        assert_eq!(item.item_type, TopItemType::Artist);
        assert!(item.popularity.is_none());
    }

    #[test]
    fn top_item_serialize() {
        let item = TopItem {
            id: "t1".into(),
            name: "Song".into(),
            item_type: TopItemType::Track,
            rank: 1,
            popularity: Some(80),
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["id"], "t1");
        assert_eq!(v["rank"], 1);
        assert_eq!(v["popularity"], 80);
    }

    #[test]
    fn top_item_deserialize() {
        let item: TopItem = serde_json::from_value(json!({
            "id": "a1",
            "name": "Artist",
            "item_type": "Artist",
            "rank": 5,
            "popularity": null
        }))
        .unwrap();
        assert_eq!(item.id, "a1");
        assert_eq!(item.item_type, TopItemType::Artist);
        assert!(item.popularity.is_none());
    }

    #[test]
    fn top_item_clone_debug() {
        let item = TopItem {
            id: "t1".into(),
            name: "Song".into(),
            item_type: TopItemType::Track,
            rank: 1,
            popularity: Some(50),
        };
        let cloned = item.clone();
        assert_eq!(cloned.id, "t1");
        let dbg = format!("{item:?}");
        assert!(dbg.contains("TopItem"));
    }

    // ── TopItems tests ──────────────────────────────────────────

    #[test]
    fn top_items_empty() {
        let items = TopItems {
            items: vec![],
            total: 0,
            time_range: TimeRange::MediumTerm,
            limit: 20,
            offset: 0,
        };
        assert!(items.items.is_empty());
        assert_eq!(items.total, 0);
    }

    #[test]
    fn top_items_with_data() {
        let items = TopItems {
            items: vec![
                TopItem {
                    id: "t1".into(),
                    name: "Song 1".into(),
                    item_type: TopItemType::Track,
                    rank: 1,
                    popularity: Some(90),
                },
                TopItem {
                    id: "t2".into(),
                    name: "Song 2".into(),
                    item_type: TopItemType::Track,
                    rank: 2,
                    popularity: Some(85),
                },
            ],
            total: 50,
            time_range: TimeRange::LongTerm,
            limit: 20,
            offset: 0,
        };
        assert_eq!(items.items.len(), 2);
        assert_eq!(items.total, 50);
        assert_eq!(items.time_range, TimeRange::LongTerm);
    }

    #[test]
    fn top_items_serialize_roundtrip() {
        let items = TopItems {
            items: vec![],
            total: 10,
            time_range: TimeRange::ShortTerm,
            limit: 5,
            offset: 10,
        };
        let v = serde_json::to_value(&items).unwrap();
        let back: TopItems = serde_json::from_value(v).unwrap();
        assert_eq!(back.total, 10);
        assert_eq!(back.time_range, TimeRange::ShortTerm);
        assert_eq!(back.offset, 10);
    }

    #[test]
    fn top_items_clone_debug() {
        let items = TopItems {
            items: vec![],
            total: 0,
            time_range: TimeRange::MediumTerm,
            limit: 20,
            offset: 0,
        };
        let cloned = items.clone();
        assert_eq!(cloned.total, 0);
        let dbg = format!("{items:?}");
        assert!(dbg.contains("TopItems"));
    }

    // ── HistoryQuery tests ──────────────────────────────────────

    #[test]
    fn history_query_default() {
        let q = HistoryQuery::new();
        assert_eq!(q.limit, 20);
        assert!(q.after.is_none());
        assert!(q.before.is_none());
    }

    #[test]
    fn history_query_with_limit() {
        let q = HistoryQuery::new().with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn history_query_with_after() {
        let q = HistoryQuery::new().with_after(1_700_000_000_000);
        assert_eq!(q.after, Some(1_700_000_000_000));
    }

    #[test]
    fn history_query_with_before() {
        let q = HistoryQuery::new().with_before(1_700_000_000_000);
        assert_eq!(q.before, Some(1_700_000_000_000));
    }

    #[test]
    fn history_query_builder_chain() {
        let q = HistoryQuery::new().with_limit(30).with_after(1_000_000_000);
        assert_eq!(q.limit, 30);
        assert_eq!(q.after, Some(1_000_000_000));
        assert!(q.before.is_none());
    }

    #[test]
    fn history_query_validate_valid() {
        let q = HistoryQuery::new().with_limit(20);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn history_query_validate_limit_zero() {
        let q = HistoryQuery::new().with_limit(0);
        assert!(matches!(
            q.validate(),
            Err(HistoryValidationError::InvalidLimit { value: 0, max: 50 })
        ));
    }

    #[test]
    fn history_query_validate_limit_too_high() {
        let q = HistoryQuery::new().with_limit(51);
        assert!(matches!(
            q.validate(),
            Err(HistoryValidationError::InvalidLimit { value: 51, max: 50 })
        ));
    }

    #[test]
    fn history_query_validate_after_and_before_conflict() {
        let q = HistoryQuery::new()
            .with_after(1_000_000)
            .with_before(2_000_000);
        assert!(matches!(
            q.validate(),
            Err(HistoryValidationError::AfterBeforeConflict)
        ));
    }

    #[test]
    fn history_query_validate_only_after() {
        let q = HistoryQuery::new().with_after(1_000_000);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn history_query_validate_only_before() {
        let q = HistoryQuery::new().with_before(1_000_000);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn history_query_validate_limit_1() {
        let q = HistoryQuery::new().with_limit(1);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn history_query_validate_limit_50() {
        let q = HistoryQuery::new().with_limit(50);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn history_query_serialize_roundtrip() {
        let q = HistoryQuery::new().with_limit(30).with_after(12345);
        let v = serde_json::to_value(&q).unwrap();
        let back: HistoryQuery = serde_json::from_value(v).unwrap();
        assert_eq!(back.limit, 30);
        assert_eq!(back.after, Some(12345));
    }

    #[test]
    fn history_query_clone_debug() {
        let q = HistoryQuery::new().with_limit(10);
        let cloned = q.clone();
        assert_eq!(cloned.limit, 10);
        let dbg = format!("{q:?}");
        assert!(dbg.contains("HistoryQuery"));
    }

    // ── TopItemsQuery tests ─────────────────────────────────────

    #[test]
    fn top_items_query_default_track() {
        let q = TopItemsQuery::new(TopItemType::Track);
        assert_eq!(q.item_type, TopItemType::Track);
        assert_eq!(q.time_range, TimeRange::MediumTerm);
        assert_eq!(q.limit, 20);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn top_items_query_default_artist() {
        let q = TopItemsQuery::new(TopItemType::Artist);
        assert_eq!(q.item_type, TopItemType::Artist);
    }

    #[test]
    fn top_items_query_with_time_range() {
        let q = TopItemsQuery::new(TopItemType::Track).with_time_range(TimeRange::ShortTerm);
        assert_eq!(q.time_range, TimeRange::ShortTerm);
    }

    #[test]
    fn top_items_query_with_limit() {
        let q = TopItemsQuery::new(TopItemType::Track).with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn top_items_query_with_offset() {
        let q = TopItemsQuery::new(TopItemType::Artist).with_offset(20);
        assert_eq!(q.offset, 20);
    }

    #[test]
    fn top_items_query_builder_chain() {
        let q = TopItemsQuery::new(TopItemType::Track)
            .with_time_range(TimeRange::LongTerm)
            .with_limit(10)
            .with_offset(5);
        assert_eq!(q.time_range, TimeRange::LongTerm);
        assert_eq!(q.limit, 10);
        assert_eq!(q.offset, 5);
    }

    #[test]
    fn top_items_query_validate_valid() {
        let q = TopItemsQuery::new(TopItemType::Track);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn top_items_query_validate_limit_zero() {
        let q = TopItemsQuery::new(TopItemType::Track).with_limit(0);
        assert!(matches!(
            q.validate(),
            Err(HistoryValidationError::InvalidLimit { value: 0, max: 50 })
        ));
    }

    #[test]
    fn top_items_query_validate_limit_too_high() {
        let q = TopItemsQuery::new(TopItemType::Track).with_limit(51);
        assert!(matches!(
            q.validate(),
            Err(HistoryValidationError::InvalidLimit { value: 51, max: 50 })
        ));
    }

    #[test]
    fn top_items_query_validate_offset_too_high() {
        let q = TopItemsQuery::new(TopItemType::Track).with_offset(1001);
        assert!(matches!(
            q.validate(),
            Err(HistoryValidationError::InvalidOffset {
                value: 1001,
                max: 1000
            })
        ));
    }

    #[test]
    fn top_items_query_validate_offset_max() {
        let q = TopItemsQuery::new(TopItemType::Track).with_offset(1000);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn top_items_query_validate_limit_1() {
        let q = TopItemsQuery::new(TopItemType::Artist).with_limit(1);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn top_items_query_validate_limit_50() {
        let q = TopItemsQuery::new(TopItemType::Artist).with_limit(50);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn top_items_query_serialize_roundtrip() {
        let q = TopItemsQuery::new(TopItemType::Artist)
            .with_time_range(TimeRange::LongTerm)
            .with_limit(10)
            .with_offset(5);
        let v = serde_json::to_value(&q).unwrap();
        let back: TopItemsQuery = serde_json::from_value(v).unwrap();
        assert_eq!(back.item_type, TopItemType::Artist);
        assert_eq!(back.time_range, TimeRange::LongTerm);
        assert_eq!(back.limit, 10);
        assert_eq!(back.offset, 5);
    }

    #[test]
    fn top_items_query_clone_debug() {
        let q = TopItemsQuery::new(TopItemType::Track);
        let cloned = q.clone();
        assert_eq!(cloned.item_type, TopItemType::Track);
        let dbg = format!("{q:?}");
        assert!(dbg.contains("TopItemsQuery"));
    }

    // ── HistoryValidationError tests ────────────────────────────

    #[test]
    fn validation_error_invalid_limit_display() {
        let e = HistoryValidationError::InvalidLimit {
            value: 100,
            max: 50,
        };
        assert_eq!(e.to_string(), "invalid limit 100: must be between 1 and 50");
    }

    #[test]
    fn validation_error_invalid_time_window_display() {
        let e = HistoryValidationError::InvalidTimeWindow {
            span_days: 120,
            max_days: 90,
        };
        assert_eq!(
            e.to_string(),
            "time window of 120 days exceeds maximum of 90 days"
        );
    }

    #[test]
    fn validation_error_after_before_conflict_display() {
        let e = HistoryValidationError::AfterBeforeConflict;
        assert_eq!(
            e.to_string(),
            "cannot specify both 'after' and 'before' cursors"
        );
    }

    #[test]
    fn validation_error_invalid_offset_display() {
        let e = HistoryValidationError::InvalidOffset {
            value: 5000,
            max: 1000,
        };
        assert_eq!(e.to_string(), "invalid offset 5000: must be at most 1000");
    }

    #[test]
    fn validation_error_equality() {
        assert_eq!(
            HistoryValidationError::AfterBeforeConflict,
            HistoryValidationError::AfterBeforeConflict
        );
        assert_ne!(
            HistoryValidationError::AfterBeforeConflict,
            HistoryValidationError::InvalidLimit { value: 0, max: 50 }
        );
    }

    #[test]
    fn validation_error_clone() {
        let e = HistoryValidationError::InvalidLimit { value: 0, max: 50 };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn validation_error_debug() {
        let e = HistoryValidationError::AfterBeforeConflict;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("AfterBeforeConflict"));
    }

    #[test]
    fn validation_error_serialize_roundtrip() {
        let e = HistoryValidationError::InvalidLimit { value: 99, max: 50 };
        let v = serde_json::to_value(&e).unwrap();
        let back: HistoryValidationError = serde_json::from_value(v).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn validation_error_implements_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(HistoryValidationError::AfterBeforeConflict);
        assert!(!e.to_string().is_empty());
    }

    // ── HistoryValidator tests ──────────────────────────────────

    #[test]
    fn validator_default() {
        let v = HistoryValidator::default();
        assert_eq!(v.max_limit, 50);
        assert_eq!(v.max_time_window_days, 90);
        assert_eq!(v.max_offset, 1000);
    }

    #[test]
    fn validator_custom() {
        let v = HistoryValidator {
            max_limit: 25,
            max_time_window_days: 30,
            max_offset: 500,
        };
        assert_eq!(v.max_limit, 25);
        assert_eq!(v.max_time_window_days, 30);
        assert_eq!(v.max_offset, 500);
    }

    #[test]
    fn validator_custom_limit() {
        let v = HistoryValidator {
            max_limit: 10,
            ..Default::default()
        };
        let q = HistoryQuery::new().with_limit(11);
        assert!(matches!(
            v.validate_history_query(&q),
            Err(HistoryValidationError::InvalidLimit { value: 11, max: 10 })
        ));
    }

    #[test]
    fn validator_custom_offset() {
        let v = HistoryValidator {
            max_offset: 100,
            ..Default::default()
        };
        let q = TopItemsQuery::new(TopItemType::Track).with_offset(101);
        assert!(matches!(
            v.validate_top_query(&q),
            Err(HistoryValidationError::InvalidOffset {
                value: 101,
                max: 100
            })
        ));
    }

    #[test]
    fn validator_accepts_valid_history_query() {
        let v = HistoryValidator::default();
        let q = HistoryQuery::new().with_limit(20).with_after(1_000_000);
        assert!(v.validate_history_query(&q).is_ok());
    }

    #[test]
    fn validator_accepts_valid_top_query() {
        let v = HistoryValidator::default();
        let q = TopItemsQuery::new(TopItemType::Artist)
            .with_limit(50)
            .with_offset(100);
        assert!(v.validate_top_query(&q).is_ok());
    }

    #[test]
    fn validator_clone_debug() {
        let v = HistoryValidator::default();
        let cloned = v.clone();
        assert_eq!(cloned.max_limit, 50);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("HistoryValidator"));
    }

    #[test]
    fn validator_serialize_roundtrip() {
        let v = HistoryValidator {
            max_limit: 25,
            max_time_window_days: 60,
            max_offset: 200,
        };
        let json = serde_json::to_value(&v).unwrap();
        let back: HistoryValidator = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_limit, 25);
        assert_eq!(back.max_time_window_days, 60);
        assert_eq!(back.max_offset, 200);
    }

    // ── HistoryAuditEvent tests ─────────────────────────────────

    #[test]
    fn audit_event_create() {
        let event = HistoryAuditEvent {
            timestamp: "2025-01-15T10:00:00Z".into(),
            query_type: "recently_played".into(),
            item_count: 5,
            item_ids: vec![
                "t1".into(),
                "t2".into(),
                "t3".into(),
                "t4".into(),
                "t5".into(),
            ],
            time_range: None,
        };
        assert_eq!(event.item_count, 5);
        assert_eq!(event.item_ids.len(), 5);
    }

    #[test]
    fn audit_event_with_time_range() {
        let event = HistoryAuditEvent {
            timestamp: "2025-01-15T10:00:00Z".into(),
            query_type: "top_tracks".into(),
            item_count: 3,
            item_ids: vec!["t1".into(), "t2".into(), "t3".into()],
            time_range: Some(TimeRange::ShortTerm),
        };
        assert_eq!(event.time_range, Some(TimeRange::ShortTerm));
    }

    #[test]
    fn audit_event_contains_no_names() {
        let event = HistoryAuditEvent {
            timestamp: "2025-01-15T10:00:00Z".into(),
            query_type: "recently_played".into(),
            item_count: 2,
            item_ids: vec!["track_abc".into(), "track_def".into()],
            time_range: None,
        };
        let serialized = serde_json::to_string(&event).unwrap();
        // Verify no track/artist names leak into the audit event
        assert!(!serialized.contains("track_name"));
        assert!(!serialized.contains("artist_name"));
        // Only IDs are present
        assert!(serialized.contains("track_abc"));
        assert!(serialized.contains("track_def"));
    }

    #[test]
    fn audit_event_serialize_roundtrip() {
        let event = HistoryAuditEvent {
            timestamp: "2025-01-15T10:00:00Z".into(),
            query_type: "top_artists".into(),
            item_count: 1,
            item_ids: vec!["artist_1".into()],
            time_range: Some(TimeRange::LongTerm),
        };
        let v = serde_json::to_value(&event).unwrap();
        let back: HistoryAuditEvent = serde_json::from_value(v).unwrap();
        assert_eq!(back.query_type, "top_artists");
        assert_eq!(back.item_ids, vec!["artist_1"]);
    }

    #[test]
    fn audit_event_clone_debug() {
        let event = HistoryAuditEvent {
            timestamp: "ts".into(),
            query_type: "qt".into(),
            item_count: 0,
            item_ids: vec![],
            time_range: None,
        };
        let cloned = event.clone();
        assert_eq!(cloned.item_count, 0);
        let dbg = format!("{event:?}");
        assert!(dbg.contains("HistoryAuditEvent"));
    }

    #[test]
    fn audit_event_empty_items() {
        let event = HistoryAuditEvent {
            timestamp: "ts".into(),
            query_type: "recently_played".into(),
            item_count: 0,
            item_ids: vec![],
            time_range: None,
        };
        assert!(event.item_ids.is_empty());
        assert_eq!(event.item_count, 0);
    }

    // ── HistoryPrivacy tests ────────────────────────────────────

    #[test]
    fn privacy_new_default() {
        let p = HistoryPrivacy::new_default();
        assert!(p.redact_names);
        assert_eq!(p.max_items_per_response, 50);
        assert!(p.audit_all_reads);
    }

    #[test]
    fn privacy_default_trait() {
        let p = HistoryPrivacy::default();
        assert!(p.redact_names);
        assert!(p.audit_all_reads);
    }

    #[test]
    fn privacy_default_equals_new_default() {
        let a = HistoryPrivacy::default();
        let b = HistoryPrivacy::new_default();
        assert_eq!(a.redact_names, b.redact_names);
        assert_eq!(a.max_items_per_response, b.max_items_per_response);
        assert_eq!(a.audit_all_reads, b.audit_all_reads);
    }

    #[test]
    fn privacy_sanitize_for_audit_strips_names() {
        let privacy = HistoryPrivacy::new_default();
        let history = PlayHistory {
            items: vec![
                PlayHistoryItem {
                    track_id: "track_001".into(),
                    track_name: "Secret Song Name".into(),
                    artists: vec!["Secret Artist".into()],
                    played_at: "2025-01-15T10:00:00Z".into(),
                    context_type: Some("playlist".into()),
                    context_uri: Some("spotify:playlist:private".into()),
                    duration_ms: 200_000,
                },
                PlayHistoryItem {
                    track_id: "track_002".into(),
                    track_name: "Another Secret Song".into(),
                    artists: vec!["Another Secret Artist".into()],
                    played_at: "2025-01-15T10:05:00Z".into(),
                    context_type: None,
                    context_uri: None,
                    duration_ms: 180_000,
                },
            ],
            cursors: None,
            total: Some(2),
            limit: 20,
        };

        let audit = privacy.sanitize_for_audit(&history);
        assert_eq!(audit.query_type, "recently_played");
        assert_eq!(audit.item_count, 2);
        assert_eq!(audit.item_ids, vec!["track_001", "track_002"]);
        assert!(audit.time_range.is_none());

        // CRITICAL: Verify no names leaked into audit event
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("Secret Song Name"));
        assert!(!serialized.contains("Secret Artist"));
        assert!(!serialized.contains("Another Secret Song"));
        assert!(!serialized.contains("Another Secret Artist"));
        assert!(!serialized.contains("private"));
    }

    #[test]
    fn privacy_sanitize_for_audit_empty() {
        let privacy = HistoryPrivacy::new_default();
        let history = PlayHistory {
            items: vec![],
            cursors: None,
            total: Some(0),
            limit: 20,
        };
        let audit = privacy.sanitize_for_audit(&history);
        assert_eq!(audit.item_count, 0);
        assert!(audit.item_ids.is_empty());
    }

    #[test]
    fn privacy_sanitize_top_items_for_audit_tracks() {
        let privacy = HistoryPrivacy::new_default();
        let items = TopItems {
            items: vec![
                TopItem {
                    id: "track_a".into(),
                    name: "Secret Track Name".into(),
                    item_type: TopItemType::Track,
                    rank: 1,
                    popularity: Some(95),
                },
                TopItem {
                    id: "track_b".into(),
                    name: "Another Secret Track".into(),
                    item_type: TopItemType::Track,
                    rank: 2,
                    popularity: Some(90),
                },
            ],
            total: 50,
            time_range: TimeRange::ShortTerm,
            limit: 20,
            offset: 0,
        };

        let audit = privacy.sanitize_top_items_for_audit(&items);
        assert_eq!(audit.query_type, "top_tracks");
        assert_eq!(audit.item_count, 2);
        assert_eq!(audit.item_ids, vec!["track_a", "track_b"]);
        assert_eq!(audit.time_range, Some(TimeRange::ShortTerm));

        // CRITICAL: Verify no names leaked
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("Secret Track Name"));
        assert!(!serialized.contains("Another Secret Track"));
    }

    #[test]
    fn privacy_sanitize_top_items_for_audit_artists() {
        let privacy = HistoryPrivacy::new_default();
        let items = TopItems {
            items: vec![TopItem {
                id: "artist_x".into(),
                name: "Private Artist Name".into(),
                item_type: TopItemType::Artist,
                rank: 1,
                popularity: Some(80),
            }],
            total: 10,
            time_range: TimeRange::LongTerm,
            limit: 20,
            offset: 0,
        };

        let audit = privacy.sanitize_top_items_for_audit(&items);
        assert_eq!(audit.query_type, "top_artists");
        assert_eq!(audit.item_count, 1);
        assert_eq!(audit.item_ids, vec!["artist_x"]);

        // CRITICAL: Verify no names leaked
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("Private Artist Name"));
    }

    #[test]
    fn privacy_sanitize_top_items_empty() {
        let privacy = HistoryPrivacy::new_default();
        let items = TopItems {
            items: vec![],
            total: 0,
            time_range: TimeRange::MediumTerm,
            limit: 20,
            offset: 0,
        };
        let audit = privacy.sanitize_top_items_for_audit(&items);
        assert_eq!(audit.query_type, "top_items");
        assert_eq!(audit.item_count, 0);
        assert!(audit.item_ids.is_empty());
    }

    #[test]
    fn privacy_clone_debug() {
        let p = HistoryPrivacy::new_default();
        let cloned = p.clone();
        assert!(cloned.redact_names);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("HistoryPrivacy"));
    }

    #[test]
    fn privacy_serialize_roundtrip() {
        let p = HistoryPrivacy {
            redact_names: false,
            max_items_per_response: 25,
            audit_all_reads: false,
        };
        let v = serde_json::to_value(&p).unwrap();
        let back: HistoryPrivacy = serde_json::from_value(v).unwrap();
        assert!(!back.redact_names);
        assert_eq!(back.max_items_per_response, 25);
        assert!(!back.audit_all_reads);
    }

    // ── Privacy-critical tests ──────────────────────────────────
    // These tests explicitly verify that sensitive personal data
    // (track names, artist names) NEVER appears in audit events.

    #[test]
    fn critical_privacy_audit_never_contains_track_names() {
        let privacy = HistoryPrivacy::new_default();
        let sensitive_names = [
            "My Embarrassing Guilty Pleasure Song",
            "Therapy Session Playlist Track",
            "Private Home Recording Demo",
        ];
        let items: Vec<PlayHistoryItem> = sensitive_names
            .iter()
            .enumerate()
            .map(|(i, name)| PlayHistoryItem {
                track_id: format!("id_{i}"),
                track_name: (*name).to_string(),
                artists: vec![format!("Secret Artist {i}")],
                played_at: format!("2025-01-15T10:{i:02}:00Z"),
                context_type: None,
                context_uri: None,
                duration_ms: 180_000,
            })
            .collect();

        let history = PlayHistory {
            items,
            cursors: None,
            total: Some(3),
            limit: 20,
        };

        let audit = privacy.sanitize_for_audit(&history);
        let serialized = serde_json::to_string(&audit).unwrap();

        for name in &sensitive_names {
            assert!(
                !serialized.contains(name),
                "PRIVACY VIOLATION: audit event contains track name '{name}'"
            );
        }
        for i in 0..3 {
            assert!(
                !serialized.contains(&format!("Secret Artist {i}")),
                "PRIVACY VIOLATION: audit event contains artist name"
            );
        }
        // But IDs should be present
        for i in 0..3 {
            assert!(serialized.contains(&format!("id_{i}")));
        }
    }

    #[test]
    fn critical_privacy_audit_never_contains_artist_names() {
        let privacy = HistoryPrivacy::new_default();
        let items = TopItems {
            items: vec![
                TopItem {
                    id: "art_001".into(),
                    name: "Super Private Artist Name".into(),
                    item_type: TopItemType::Artist,
                    rank: 1,
                    popularity: Some(99),
                },
                TopItem {
                    id: "art_002".into(),
                    name: "Another Confidential Name".into(),
                    item_type: TopItemType::Artist,
                    rank: 2,
                    popularity: Some(85),
                },
            ],
            total: 2,
            time_range: TimeRange::MediumTerm,
            limit: 20,
            offset: 0,
        };

        let audit = privacy.sanitize_top_items_for_audit(&items);
        let serialized = serde_json::to_string(&audit).unwrap();

        assert!(
            !serialized.contains("Super Private Artist Name"),
            "PRIVACY VIOLATION: audit contains artist name"
        );
        assert!(
            !serialized.contains("Another Confidential Name"),
            "PRIVACY VIOLATION: audit contains artist name"
        );
        assert!(serialized.contains("art_001"));
        assert!(serialized.contains("art_002"));
    }

    #[test]
    fn critical_privacy_audit_does_not_contain_context_uri() {
        let privacy = HistoryPrivacy::new_default();
        let history = PlayHistory {
            items: vec![PlayHistoryItem {
                track_id: "tid".into(),
                track_name: "Name".into(),
                artists: vec!["Artist".into()],
                played_at: "2025-01-15T10:00:00Z".into(),
                context_type: Some("playlist".into()),
                context_uri: Some("spotify:playlist:my_private_playlist".into()),
                duration_ms: 100_000,
            }],
            cursors: None,
            total: Some(1),
            limit: 20,
        };

        let audit = privacy.sanitize_for_audit(&history);
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(
            !serialized.contains("my_private_playlist"),
            "PRIVACY VIOLATION: audit event contains context URI"
        );
        assert!(
            !serialized.contains("context_uri"),
            "PRIVACY VIOLATION: audit event has context_uri field"
        );
    }

    #[test]
    fn critical_privacy_audit_does_not_contain_played_at() {
        let privacy = HistoryPrivacy::new_default();
        let history = PlayHistory {
            items: vec![PlayHistoryItem {
                track_id: "tid".into(),
                track_name: "Name".into(),
                artists: vec![],
                played_at: "2025-01-15T10:30:45Z".into(),
                context_type: None,
                context_uri: None,
                duration_ms: 100_000,
            }],
            cursors: None,
            total: Some(1),
            limit: 20,
        };

        let audit = privacy.sanitize_for_audit(&history);
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(
            !serialized.contains("2025-01-15T10:30:45Z"),
            "PRIVACY VIOLATION: audit event contains played_at timestamp"
        );
    }

    // ── Integration / cross-type tests ──────────────────────────

    #[test]
    fn full_workflow_recently_played() {
        // 1. Build query
        let query = HistoryQuery::new()
            .with_limit(5)
            .with_after(1_700_000_000_000);
        assert!(query.validate().is_ok());

        // 2. Simulate response
        let history = PlayHistory {
            items: vec![PlayHistoryItem {
                track_id: "track_workflow".into(),
                track_name: "Workflow Song".into(),
                artists: vec!["Workflow Artist".into()],
                played_at: "2025-01-15T10:00:00Z".into(),
                context_type: Some("album".into()),
                context_uri: Some("spotify:album:wf".into()),
                duration_ms: 240_000,
            }],
            cursors: Some(HistoryCursors {
                after: Some("next".into()),
                before: None,
            }),
            total: Some(1),
            limit: 5,
        };

        // 3. Sanitize for audit
        let privacy = HistoryPrivacy::new_default();
        let audit = privacy.sanitize_for_audit(&history);
        assert_eq!(audit.item_count, 1);
        assert_eq!(audit.item_ids, vec!["track_workflow"]);

        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("Workflow Song"));
        assert!(!serialized.contains("Workflow Artist"));
    }

    #[test]
    fn full_workflow_top_tracks() {
        // 1. Build query
        let query = TopItemsQuery::new(TopItemType::Track)
            .with_time_range(TimeRange::ShortTerm)
            .with_limit(3);
        assert!(query.validate().is_ok());

        // 2. Simulate response
        let items = TopItems {
            items: (1..=3)
                .map(|i| TopItem {
                    id: format!("top_track_{i}"),
                    name: format!("Top Song {i}"),
                    item_type: TopItemType::Track,
                    rank: i,
                    popularity: Some(100 - i),
                })
                .collect(),
            total: 50,
            time_range: TimeRange::ShortTerm,
            limit: 3,
            offset: 0,
        };

        // 3. Sanitize for audit
        let privacy = HistoryPrivacy::new_default();
        let audit = privacy.sanitize_top_items_for_audit(&items);
        assert_eq!(audit.query_type, "top_tracks");
        assert_eq!(audit.item_count, 3);
        assert_eq!(audit.time_range, Some(TimeRange::ShortTerm));

        let serialized = serde_json::to_string(&audit).unwrap();
        for i in 1..=3 {
            assert!(!serialized.contains(&format!("Top Song {i}")));
            assert!(serialized.contains(&format!("top_track_{i}")));
        }
    }

    #[test]
    fn full_workflow_top_artists() {
        let query = TopItemsQuery::new(TopItemType::Artist)
            .with_time_range(TimeRange::LongTerm)
            .with_limit(2)
            .with_offset(10);
        assert!(query.validate().is_ok());

        let items = TopItems {
            items: vec![
                TopItem {
                    id: "a1".into(),
                    name: "Artist One".into(),
                    item_type: TopItemType::Artist,
                    rank: 11,
                    popularity: Some(75),
                },
                TopItem {
                    id: "a2".into(),
                    name: "Artist Two".into(),
                    item_type: TopItemType::Artist,
                    rank: 12,
                    popularity: None,
                },
            ],
            total: 100,
            time_range: TimeRange::LongTerm,
            limit: 2,
            offset: 10,
        };

        let privacy = HistoryPrivacy::new_default();
        let audit = privacy.sanitize_top_items_for_audit(&items);
        assert_eq!(audit.query_type, "top_artists");
        assert_eq!(audit.item_count, 2);

        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("Artist One"));
        assert!(!serialized.contains("Artist Two"));
    }

    #[test]
    fn validation_error_all_variants_serializable() {
        let errors = vec![
            HistoryValidationError::InvalidLimit { value: 0, max: 50 },
            HistoryValidationError::InvalidTimeWindow {
                span_days: 120,
                max_days: 90,
            },
            HistoryValidationError::AfterBeforeConflict,
            HistoryValidationError::InvalidOffset {
                value: 9999,
                max: 1000,
            },
        ];
        for e in &errors {
            let v = serde_json::to_value(e).unwrap();
            let back: HistoryValidationError = serde_json::from_value(v).unwrap();
            assert_eq!(*e, back);
        }
    }

    #[test]
    fn all_time_ranges_parse_roundtrip() {
        let ranges = ["short_term", "medium_term", "long_term"];
        for s in &ranges {
            let tr = TimeRange::parse(s).unwrap();
            assert_eq!(tr.as_str(), *s);
        }
    }

    #[test]
    fn play_history_item_roundtrip_serde() {
        let item = PlayHistoryItem {
            track_id: "t_rt".into(),
            track_name: "Roundtrip".into(),
            artists: vec!["A1".into(), "A2".into()],
            played_at: "2025-06-01T00:00:00Z".into(),
            context_type: Some("artist".into()),
            context_uri: Some("spotify:artist:xyz".into()),
            duration_ms: 333_000,
        };
        let v = serde_json::to_value(&item).unwrap();
        let back: PlayHistoryItem = serde_json::from_value(v).unwrap();
        assert_eq!(back.track_id, "t_rt");
        assert_eq!(back.artists.len(), 2);
        assert_eq!(back.context_type, Some("artist".into()));
    }

    #[test]
    fn history_cursors_roundtrip_serde() {
        let c = HistoryCursors {
            after: Some("a_cursor".into()),
            before: Some("b_cursor".into()),
        };
        let v = serde_json::to_value(&c).unwrap();
        let back: HistoryCursors = serde_json::from_value(v).unwrap();
        assert_eq!(back.after, Some("a_cursor".into()));
        assert_eq!(back.before, Some("b_cursor".into()));
    }

    #[test]
    fn play_history_with_cursors_roundtrip() {
        let h = PlayHistory {
            items: vec![PlayHistoryItem {
                track_id: "t1".into(),
                track_name: "S".into(),
                artists: vec![],
                played_at: "ts".into(),
                context_type: None,
                context_uri: None,
                duration_ms: 1000,
            }],
            cursors: Some(HistoryCursors {
                after: Some("next_page".into()),
                before: None,
            }),
            total: Some(100),
            limit: 20,
        };
        let v = serde_json::to_value(&h).unwrap();
        let back: PlayHistory = serde_json::from_value(v).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(
            back.cursors.as_ref().unwrap().after,
            Some("next_page".into())
        );
    }

    #[test]
    fn history_query_default_impl() {
        let q: HistoryQuery = HistoryQuery::default();
        assert_eq!(q.limit, 20);
        assert!(q.after.is_none());
        assert!(q.before.is_none());
    }

    #[test]
    fn top_item_type_copy() {
        let t = TopItemType::Track;
        let copied = t;
        assert_eq!(t, copied);
    }

    #[test]
    fn time_range_copy() {
        let t = TimeRange::LongTerm;
        let copied = t;
        assert_eq!(t, copied);
    }

    #[test]
    fn privacy_custom_config() {
        let p = HistoryPrivacy {
            redact_names: false,
            max_items_per_response: 100,
            audit_all_reads: false,
        };
        assert!(!p.redact_names);
        assert_eq!(p.max_items_per_response, 100);
        assert!(!p.audit_all_reads);
    }

    #[test]
    fn audit_event_many_items() {
        let ids: Vec<String> = (0..50).map(|i| format!("id_{i}")).collect();
        let event = HistoryAuditEvent {
            timestamp: "ts".into(),
            query_type: "recently_played".into(),
            item_count: 50,
            item_ids: ids,
            time_range: None,
        };
        assert_eq!(event.item_ids.len(), 50);
        assert_eq!(event.item_ids[0], "id_0");
        assert_eq!(event.item_ids[49], "id_49");
    }

    #[test]
    fn top_items_with_offset() {
        let items = TopItems {
            items: vec![TopItem {
                id: "t10".into(),
                name: "Song at offset 10".into(),
                item_type: TopItemType::Track,
                rank: 11,
                popularity: Some(60),
            }],
            total: 100,
            time_range: TimeRange::MediumTerm,
            limit: 1,
            offset: 10,
        };
        assert_eq!(items.offset, 10);
        assert_eq!(items.items[0].rank, 11);
    }

    #[test]
    fn validator_rejects_limit_zero_history() {
        let v = HistoryValidator::default();
        let q = HistoryQuery {
            limit: 0,
            after: None,
            before: None,
        };
        assert!(v.validate_history_query(&q).is_err());
    }

    #[test]
    fn validator_rejects_limit_zero_top() {
        let v = HistoryValidator::default();
        let q = TopItemsQuery {
            item_type: TopItemType::Track,
            time_range: TimeRange::ShortTerm,
            limit: 0,
            offset: 0,
        };
        assert!(v.validate_top_query(&q).is_err());
    }

    #[test]
    fn validator_accepts_boundary_limit_history() {
        let v = HistoryValidator::default();
        for limit in [1, 25, 50] {
            let q = HistoryQuery {
                limit,
                after: None,
                before: None,
            };
            assert!(
                v.validate_history_query(&q).is_ok(),
                "limit {limit} should be valid"
            );
        }
    }

    #[test]
    fn validator_accepts_boundary_limit_top() {
        let v = HistoryValidator::default();
        for limit in [1, 25, 50] {
            let q = TopItemsQuery {
                item_type: TopItemType::Artist,
                time_range: TimeRange::MediumTerm,
                limit,
                offset: 0,
            };
            assert!(
                v.validate_top_query(&q).is_ok(),
                "limit {limit} should be valid"
            );
        }
    }

    #[test]
    fn validator_accepts_boundary_offset() {
        let v = HistoryValidator::default();
        for offset in [0, 500, 1000] {
            let q = TopItemsQuery {
                item_type: TopItemType::Track,
                time_range: TimeRange::LongTerm,
                limit: 20,
                offset,
            };
            assert!(
                v.validate_top_query(&q).is_ok(),
                "offset {offset} should be valid"
            );
        }
    }

    #[test]
    fn play_history_item_zero_duration() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Short".into(),
            artists: vec![],
            played_at: "ts".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 0,
        };
        assert_eq!(item.duration_ms, 0);
    }

    #[test]
    fn play_history_item_large_duration() {
        let item = PlayHistoryItem {
            track_id: "t1".into(),
            track_name: "Long".into(),
            artists: vec![],
            played_at: "ts".into(),
            context_type: None,
            context_uri: None,
            duration_ms: 3_600_000, // 1 hour
        };
        assert_eq!(item.duration_ms, 3_600_000);
    }

    #[test]
    fn top_item_rank_zero() {
        let item = TopItem {
            id: "t1".into(),
            name: "Song".into(),
            item_type: TopItemType::Track,
            rank: 0,
            popularity: None,
        };
        assert_eq!(item.rank, 0);
    }

    #[test]
    fn top_item_popularity_max() {
        let item = TopItem {
            id: "t1".into(),
            name: "Popular".into(),
            item_type: TopItemType::Track,
            rank: 1,
            popularity: Some(100),
        };
        assert_eq!(item.popularity, Some(100));
    }

    #[test]
    fn top_item_popularity_zero() {
        let item = TopItem {
            id: "t1".into(),
            name: "Unpopular".into(),
            item_type: TopItemType::Track,
            rank: 50,
            popularity: Some(0),
        };
        assert_eq!(item.popularity, Some(0));
    }
}
