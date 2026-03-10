//! `Reddit` saved items management.
//!
//! Provides types for managing saved posts and comments on `Reddit`,
//! including save/unsave actions, pagination, validation, and policy enforcement.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── SavedItemType ────────────────────────────────────────────────────

/// The type of a saved `Reddit` item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedItemType {
    /// A saved post (link or self-post).
    Post,
    /// A saved comment.
    Comment,
}

impl SavedItemType {
    /// Returns the string representation of the item type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Post => "post",
            Self::Comment => "comment",
        }
    }
}

impl fmt::Display for SavedItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── SavedItem ────────────────────────────────────────────────────────

/// A saved `Reddit` item (post or comment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedItem {
    /// The fullname identifier (e.g. `t3_abc123` for posts, `t1_xyz` for comments).
    pub id: String,
    /// Whether this is a post or a comment.
    pub item_type: SavedItemType,
    /// The title of the item. Comments do not have titles, so this is `None` for comments.
    pub title: Option<String>,
    /// The subreddit the item belongs to.
    pub subreddit: String,
    /// The author of the item.
    pub author: String,
    /// The score (upvotes minus downvotes).
    pub score: i64,
    /// The UTC timestamp when the item was created.
    pub created_utc: f64,
    /// The UTC timestamp when the item was saved, if available.
    pub saved_at: Option<f64>,
    /// The permalink to the item on `Reddit`.
    pub permalink: String,
    /// A preview of the body text (first 200 characters). Only present for comments.
    pub body_preview: Option<String>,
}

impl SavedItem {
    /// Returns `true` if this is a saved post.
    #[must_use]
    pub const fn is_post(&self) -> bool {
        matches!(self.item_type, SavedItemType::Post)
    }

    /// Returns `true` if this is a saved comment.
    #[must_use]
    pub const fn is_comment(&self) -> bool {
        matches!(self.item_type, SavedItemType::Comment)
    }

    /// Returns the body preview, truncated to `max_len` characters.
    #[must_use]
    pub fn truncated_preview(&self, max_len: usize) -> Option<String> {
        self.body_preview.as_ref().map(|body| {
            if body.len() <= max_len {
                body.clone()
            } else {
                let mut truncated: String = body.chars().take(max_len).collect();
                truncated.push_str("...");
                truncated
            }
        })
    }
}

// ── SavedItemsPage ───────────────────────────────────────────────────

/// A page of saved `Reddit` items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedItemsPage {
    /// The saved items on this page.
    pub items: Vec<SavedItem>,
    /// Cursor for the next page, if available.
    pub after: Option<String>,
    /// Cursor for the previous page, if available.
    pub before: Option<String>,
    /// The total count of items fetched so far (for pagination offset).
    pub count: u32,
    /// Whether there are more items to fetch.
    pub has_more: bool,
}

impl SavedItemsPage {
    /// Returns an empty page with no items.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            items: Vec::new(),
            after: None,
            before: None,
            count: 0,
            has_more: false,
        }
    }

    /// Returns the number of items on this page.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if there are no items on this page.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns an iterator over the items filtered by type.
    pub fn items_of_type(&self, item_type: SavedItemType) -> impl Iterator<Item = &SavedItem> {
        self.items
            .iter()
            .filter(move |item| item.item_type == item_type)
    }

    /// Returns the number of posts on this page.
    #[must_use]
    pub fn post_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.item_type == SavedItemType::Post)
            .count()
    }

    /// Returns the number of comments on this page.
    #[must_use]
    pub fn comment_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.item_type == SavedItemType::Comment)
            .count()
    }
}

// ── SavedItemsQuery ──────────────────────────────────────────────────

/// Maximum number of items per page.
const MAX_LIMIT: u32 = 100;

/// Default number of items per page.
const DEFAULT_LIMIT: u32 = 25;

/// Query parameters for listing saved `Reddit` items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedItemsQuery {
    /// Number of items per page (default 25, max 100).
    pub limit: u32,
    /// Cursor for fetching the next page.
    pub after: Option<String>,
    /// Cursor for fetching the previous page.
    pub before: Option<String>,
    /// Filter by item type (post or comment).
    pub item_type_filter: Option<SavedItemType>,
    /// Filter by subreddit name.
    pub subreddit_filter: Option<String>,
}

impl SavedItemsQuery {
    /// Creates a new query with default parameters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            after: None,
            before: None,
            item_type_filter: None,
            subreddit_filter: None,
        }
    }

    /// Sets the page size limit.
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Sets the `after` pagination cursor.
    #[must_use]
    pub fn with_after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    /// Sets the `before` pagination cursor.
    #[must_use]
    pub fn with_before(mut self, before: impl Into<String>) -> Self {
        self.before = Some(before.into());
        self
    }

    /// Filters results to a specific item type.
    #[must_use]
    pub const fn filter_type(mut self, item_type: SavedItemType) -> Self {
        self.item_type_filter = Some(item_type);
        self
    }

    /// Filters results to a specific subreddit.
    #[must_use]
    pub fn filter_subreddit(mut self, subreddit: impl Into<String>) -> Self {
        self.subreddit_filter = Some(subreddit.into());
        self
    }

    /// Validates the query parameters.
    ///
    /// # Errors
    ///
    /// Returns `SavedValidationError::InvalidLimit` if the limit is 0 or exceeds 100.
    pub const fn validate(&self) -> Result<(), SavedValidationError> {
        if self.limit == 0 || self.limit > MAX_LIMIT {
            return Err(SavedValidationError::InvalidLimit {
                value: self.limit,
                max: MAX_LIMIT,
            });
        }
        Ok(())
    }
}

impl Default for SavedItemsQuery {
    fn default() -> Self {
        Self::new()
    }
}

// ── SaveAction ───────────────────────────────────────────────────────

/// An action to save or unsave a `Reddit` item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SaveAction {
    /// Save an item by its fullname.
    Save {
        /// The fullname of the item (e.g. `t3_abc123`).
        thing_id: String,
    },
    /// Unsave a previously saved item.
    Unsave {
        /// The fullname of the item (e.g. `t1_xyz`).
        thing_id: String,
    },
}

impl SaveAction {
    /// Returns the thing ID for this action.
    #[must_use]
    pub fn thing_id(&self) -> &str {
        match self {
            Self::Save { thing_id } | Self::Unsave { thing_id } => thing_id,
        }
    }

    /// Returns `true` if this is a save action.
    #[must_use]
    pub const fn is_save(&self) -> bool {
        matches!(self, Self::Save { .. })
    }

    /// Returns `true` if this is an unsave action.
    #[must_use]
    pub const fn is_unsave(&self) -> bool {
        matches!(self, Self::Unsave { .. })
    }

    /// Validates the action parameters.
    ///
    /// Checks that the `thing_id` is non-empty and matches the `Reddit` fullname format
    /// (e.g. `t1_`, `t2_`, `t3_`, `t4_`, `t5_`, `t6_` prefix followed by alphanumeric characters).
    ///
    /// # Errors
    ///
    /// Returns `SavedValidationError::EmptyThingId` if the thing ID is empty.
    /// Returns `SavedValidationError::InvalidThingId` if the format is wrong.
    pub fn validate(&self) -> Result<(), SavedValidationError> {
        let id = self.thing_id();
        if id.is_empty() {
            return Err(SavedValidationError::EmptyThingId);
        }

        // Reddit fullnames are like t1_abc123, t3_xyz789, etc.
        let valid_prefixes = ["t1_", "t2_", "t3_", "t4_", "t5_", "t6_"];
        let has_valid_prefix = valid_prefixes.iter().any(|p| id.starts_with(p));
        if !has_valid_prefix {
            return Err(SavedValidationError::InvalidThingId {
                value: id.to_string(),
                reason: "must start with a valid type prefix (t1_-t6_)".into(),
            });
        }

        let suffix = &id[3..];
        if suffix.is_empty() {
            return Err(SavedValidationError::InvalidThingId {
                value: id.to_string(),
                reason: "ID suffix after prefix must not be empty".into(),
            });
        }

        if !suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(SavedValidationError::InvalidThingId {
                value: id.to_string(),
                reason: "ID suffix must be alphanumeric".into(),
            });
        }

        Ok(())
    }
}

impl fmt::Display for SaveAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Save { thing_id } => write!(f, "save({thing_id})"),
            Self::Unsave { thing_id } => write!(f, "unsave({thing_id})"),
        }
    }
}

// ── SaveResult ───────────────────────────────────────────────────────

/// The result of a save or unsave action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveResult {
    /// The action that was performed.
    pub action: SaveAction,
    /// The fullname of the item that was acted upon.
    pub thing_id: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// An error message if the action failed.
    pub error_message: Option<String>,
}

impl SaveResult {
    /// Creates a successful result.
    #[must_use]
    pub fn success(action: SaveAction) -> Self {
        let thing_id = action.thing_id().to_string();
        Self {
            action,
            thing_id,
            success: true,
            error_message: None,
        }
    }

    /// Creates a failed result with an error message.
    #[must_use]
    pub fn failure(action: SaveAction, error: impl Into<String>) -> Self {
        let thing_id = action.thing_id().to_string();
        Self {
            action,
            thing_id,
            success: false,
            error_message: Some(error.into()),
        }
    }
}

// ── SavedValidationError ─────────────────────────────────────────────

/// Validation errors for saved items operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SavedValidationError {
    /// The requested limit is out of range.
    InvalidLimit {
        /// The invalid value.
        value: u32,
        /// The maximum allowed value.
        max: u32,
    },
    /// The thing ID format is invalid.
    InvalidThingId {
        /// The invalid value.
        value: String,
        /// The reason it was rejected.
        reason: String,
    },
    /// The thing ID is empty.
    EmptyThingId,
}

impl fmt::Display for SavedValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { value, max } => {
                write!(f, "invalid limit {value}: must be between 1 and {max}")
            }
            Self::InvalidThingId { value, reason } => {
                write!(f, "invalid thing ID '{value}': {reason}")
            }
            Self::EmptyThingId => write!(f, "thing ID must not be empty"),
        }
    }
}

impl std::error::Error for SavedValidationError {}

// ── SavedItemsValidator ──────────────────────────────────────────────

/// Validates saved items queries and actions.
#[derive(Debug, Clone)]
pub struct SavedItemsValidator {
    /// Maximum number of items per page.
    pub max_limit: u32,
    /// The set of allowed item types.
    pub allowed_types: HashSet<SavedItemType>,
}

impl SavedItemsValidator {
    /// Creates a new validator with the default configuration.
    #[must_use]
    pub fn new() -> Self {
        let mut allowed_types = HashSet::new();
        allowed_types.insert(SavedItemType::Post);
        allowed_types.insert(SavedItemType::Comment);
        Self {
            max_limit: MAX_LIMIT,
            allowed_types,
        }
    }

    /// Validates a saved items query.
    ///
    /// # Errors
    ///
    /// Returns `SavedValidationError::InvalidLimit` if the limit is out of range.
    pub const fn validate_query(
        &self,
        query: &SavedItemsQuery,
    ) -> Result<(), SavedValidationError> {
        if query.limit == 0 || query.limit > self.max_limit {
            return Err(SavedValidationError::InvalidLimit {
                value: query.limit,
                max: self.max_limit,
            });
        }
        Ok(())
    }

    /// Validates a save/unsave action.
    ///
    /// # Errors
    ///
    /// Returns a `SavedValidationError` if the action is invalid.
    pub fn validate_action(&self, action: &SaveAction) -> Result<(), SavedValidationError> {
        action.validate()
    }
}

impl Default for SavedItemsValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── SavedItemsPolicy ─────────────────────────────────────────────────

/// Policy for controlling access to saved items operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedItemsPolicy {
    /// Whether reading saved items is allowed.
    pub allow_read: bool,
    /// Whether saving items is allowed.
    pub allow_save: bool,
    /// Whether unsaving items is allowed.
    pub allow_unsave: bool,
}

impl SavedItemsPolicy {
    /// Creates a fully permissive policy.
    #[must_use]
    pub const fn new_permissive() -> Self {
        Self {
            allow_read: true,
            allow_save: true,
            allow_unsave: true,
        }
    }

    /// Creates a read-only policy.
    #[must_use]
    pub const fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_save: false,
            allow_unsave: false,
        }
    }

    /// Checks whether a given action is permitted by this policy.
    #[must_use]
    pub const fn check_action(&self, action: &SaveAction) -> bool {
        match action {
            SaveAction::Save { .. } => self.allow_save,
            SaveAction::Unsave { .. } => self.allow_unsave,
        }
    }
}

// ── SavedAuditEvent ──────────────────────────────────────────────────

/// An audit event for saved items operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedAuditEvent {
    /// Timestamp of the event (UTC seconds since epoch).
    pub timestamp: f64,
    /// The type of action performed (e.g. "save", "unsave", "list").
    pub action_type: String,
    /// The thing ID involved, if applicable.
    pub thing_id: Option<String>,
    /// Whether the action was allowed by policy.
    pub was_allowed: bool,
}

impl SavedAuditEvent {
    /// Creates a new audit event for a save/unsave action.
    #[must_use]
    pub fn from_action(timestamp: f64, action: &SaveAction, was_allowed: bool) -> Self {
        Self {
            timestamp,
            action_type: if action.is_save() {
                "save".into()
            } else {
                "unsave".into()
            },
            thing_id: Some(action.thing_id().to_string()),
            was_allowed,
        }
    }

    /// Creates a new audit event for a list operation.
    #[must_use]
    pub fn for_list(timestamp: f64, was_allowed: bool) -> Self {
        Self {
            timestamp,
            action_type: "list".into(),
            thing_id: None,
            was_allowed,
        }
    }
}

// ── Helper: body preview truncation ──────────────────────────────────

/// Truncates a body string to a maximum of 200 characters for preview.
#[must_use]
pub fn make_body_preview(body: &str) -> String {
    let chars: Vec<char> = body.chars().collect();
    if chars.len() <= 200 {
        body.to_string()
    } else {
        let truncated: String = chars[..200].iter().collect();
        format!("{truncated}...")
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── helper ────────────────────────────────────────────────────────

    fn sample_post() -> SavedItem {
        SavedItem {
            id: "t3_abc123".into(),
            item_type: SavedItemType::Post,
            title: Some("Interesting Post".into()),
            subreddit: "rust".into(),
            author: "rustacean".into(),
            score: 256,
            created_utc: 1_709_600_000.0,
            saved_at: Some(1_709_600_100.0),
            permalink: "/r/rust/comments/abc123/interesting_post/".into(),
            body_preview: None,
        }
    }

    fn sample_comment() -> SavedItem {
        SavedItem {
            id: "t1_xyz789".into(),
            item_type: SavedItemType::Comment,
            title: None,
            subreddit: "programming".into(),
            author: "commenter42".into(),
            score: 18,
            created_utc: 1_709_601_000.0,
            saved_at: None,
            permalink: "/r/programming/comments/def456/post/xyz789/".into(),
            body_preview: Some("This is a great explanation of lifetimes in Rust.".into()),
        }
    }

    // ── SavedItemType ────────────────────────────────────────────────

    #[test]
    fn item_type_as_str_post() {
        assert_eq!(SavedItemType::Post.as_str(), "post");
    }

    #[test]
    fn item_type_as_str_comment() {
        assert_eq!(SavedItemType::Comment.as_str(), "comment");
    }

    #[test]
    fn item_type_display_post() {
        assert_eq!(SavedItemType::Post.to_string(), "post");
    }

    #[test]
    fn item_type_display_comment() {
        assert_eq!(SavedItemType::Comment.to_string(), "comment");
    }

    #[test]
    fn item_type_equality() {
        assert_eq!(SavedItemType::Post, SavedItemType::Post);
        assert_eq!(SavedItemType::Comment, SavedItemType::Comment);
        assert_ne!(SavedItemType::Post, SavedItemType::Comment);
    }

    #[test]
    fn item_type_hash() {
        let mut set = HashSet::new();
        set.insert(SavedItemType::Post);
        set.insert(SavedItemType::Comment);
        set.insert(SavedItemType::Post); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn item_type_clone() {
        let t = SavedItemType::Post;
        #[allow(clippy::clone_on_copy)]
        let t2 = t.clone();
        assert_eq!(t, t2);
    }

    #[test]
    fn item_type_debug() {
        let dbg = format!("{:?}", SavedItemType::Post);
        assert!(dbg.contains("Post"));
    }

    #[test]
    fn item_type_serialize_post() {
        let v = serde_json::to_value(SavedItemType::Post).unwrap();
        assert_eq!(v, json!("post"));
    }

    #[test]
    fn item_type_serialize_comment() {
        let v = serde_json::to_value(SavedItemType::Comment).unwrap();
        assert_eq!(v, json!("comment"));
    }

    #[test]
    fn item_type_deserialize_post() {
        let t: SavedItemType = serde_json::from_value(json!("post")).unwrap();
        assert_eq!(t, SavedItemType::Post);
    }

    #[test]
    fn item_type_deserialize_comment() {
        let t: SavedItemType = serde_json::from_value(json!("comment")).unwrap();
        assert_eq!(t, SavedItemType::Comment);
    }

    #[test]
    fn item_type_deserialize_invalid() {
        let result = serde_json::from_value::<SavedItemType>(json!("link"));
        assert!(result.is_err());
    }

    #[test]
    fn item_type_copy() {
        let t = SavedItemType::Post;
        let t2 = t; // copy
        assert_eq!(t, t2); // original still usable
    }

    // ── SavedItem ────────────────────────────────────────────────────

    #[test]
    fn saved_item_is_post() {
        assert!(sample_post().is_post());
        assert!(!sample_post().is_comment());
    }

    #[test]
    fn saved_item_is_comment() {
        assert!(sample_comment().is_comment());
        assert!(!sample_comment().is_post());
    }

    #[test]
    fn saved_item_post_has_title() {
        assert!(sample_post().title.is_some());
    }

    #[test]
    fn saved_item_comment_has_no_title() {
        assert!(sample_comment().title.is_none());
    }

    #[test]
    fn saved_item_comment_has_body_preview() {
        assert!(sample_comment().body_preview.is_some());
    }

    #[test]
    fn saved_item_post_has_no_body_preview() {
        assert!(sample_post().body_preview.is_none());
    }

    #[test]
    fn saved_item_truncated_preview_none() {
        assert!(sample_post().truncated_preview(100).is_none());
    }

    #[test]
    fn saved_item_truncated_preview_short() {
        let item = sample_comment();
        let preview = item.truncated_preview(200).unwrap();
        assert_eq!(preview, item.body_preview.unwrap());
    }

    #[test]
    fn saved_item_truncated_preview_truncates() {
        let mut item = sample_comment();
        item.body_preview = Some("a".repeat(300));
        let preview = item.truncated_preview(50).unwrap();
        assert!(preview.ends_with("..."));
        // 50 chars + "..."
        assert_eq!(preview.len(), 53);
    }

    #[test]
    fn saved_item_serialize_roundtrip() {
        let item = sample_post();
        let v = serde_json::to_value(&item).unwrap();
        let item2: SavedItem = serde_json::from_value(v).unwrap();
        assert_eq!(item2.id, "t3_abc123");
        assert_eq!(item2.subreddit, "rust");
    }

    #[test]
    fn saved_item_comment_serialize_roundtrip() {
        let item = sample_comment();
        let v = serde_json::to_value(&item).unwrap();
        let item2: SavedItem = serde_json::from_value(v).unwrap();
        assert_eq!(item2.id, "t1_xyz789");
        assert!(item2.body_preview.is_some());
    }

    #[test]
    fn saved_item_clone() {
        let item = sample_post();
        #[allow(clippy::redundant_clone)]
        let item2 = item.clone();
        assert_eq!(item2.id, "t3_abc123");
    }

    #[test]
    fn saved_item_debug() {
        let dbg = format!("{:?}", sample_post());
        assert!(dbg.contains("abc123"));
    }

    #[test]
    fn saved_item_negative_score() {
        let mut item = sample_post();
        item.score = -42;
        assert_eq!(item.score, -42);
    }

    #[test]
    fn saved_item_saved_at_present() {
        assert!(sample_post().saved_at.is_some());
    }

    #[test]
    fn saved_item_saved_at_absent() {
        assert!(sample_comment().saved_at.is_none());
    }

    // ── SavedItemsPage ───────────────────────────────────────────────

    #[test]
    fn page_empty() {
        let page = SavedItemsPage::empty();
        assert!(page.is_empty());
        assert_eq!(page.len(), 0);
        assert!(!page.has_more);
        assert!(page.after.is_none());
        assert!(page.before.is_none());
        assert_eq!(page.count, 0);
    }

    #[test]
    fn page_with_items() {
        let page = SavedItemsPage {
            items: vec![sample_post(), sample_comment()],
            after: Some("cursor_next".into()),
            before: None,
            count: 2,
            has_more: true,
        };
        assert_eq!(page.len(), 2);
        assert!(!page.is_empty());
        assert!(page.has_more);
    }

    #[test]
    fn page_post_count() {
        let page = SavedItemsPage {
            items: vec![sample_post(), sample_comment(), sample_post()],
            after: None,
            before: None,
            count: 3,
            has_more: false,
        };
        assert_eq!(page.post_count(), 2);
    }

    #[test]
    fn page_comment_count() {
        let page = SavedItemsPage {
            items: vec![sample_post(), sample_comment(), sample_comment()],
            after: None,
            before: None,
            count: 3,
            has_more: false,
        };
        assert_eq!(page.comment_count(), 2);
    }

    #[test]
    fn page_items_of_type_post() {
        let page = SavedItemsPage {
            items: vec![sample_post(), sample_comment(), sample_post()],
            after: None,
            before: None,
            count: 3,
            has_more: false,
        };
        assert_eq!(page.items_of_type(SavedItemType::Post).count(), 2);
    }

    #[test]
    fn page_items_of_type_comment() {
        let page = SavedItemsPage {
            items: vec![sample_post(), sample_comment()],
            after: None,
            before: None,
            count: 2,
            has_more: false,
        };
        assert_eq!(page.items_of_type(SavedItemType::Comment).count(), 1);
    }

    #[test]
    fn page_serialize_roundtrip() {
        let page = SavedItemsPage {
            items: vec![sample_post()],
            after: Some("next".into()),
            before: Some("prev".into()),
            count: 25,
            has_more: true,
        };
        let v = serde_json::to_value(&page).unwrap();
        let page2: SavedItemsPage = serde_json::from_value(v).unwrap();
        assert_eq!(page2.items.len(), 1);
        assert_eq!(page2.after, Some("next".into()));
        assert_eq!(page2.before, Some("prev".into()));
        assert_eq!(page2.count, 25);
        assert!(page2.has_more);
    }

    #[test]
    fn page_clone() {
        let page = SavedItemsPage::empty();
        #[allow(clippy::redundant_clone)]
        let page2 = page.clone();
        assert!(page2.is_empty());
    }

    #[test]
    fn page_debug() {
        let dbg = format!("{:?}", SavedItemsPage::empty());
        assert!(dbg.contains("items"));
    }

    #[test]
    fn page_empty_post_count() {
        assert_eq!(SavedItemsPage::empty().post_count(), 0);
    }

    #[test]
    fn page_empty_comment_count() {
        assert_eq!(SavedItemsPage::empty().comment_count(), 0);
    }

    // ── SavedItemsQuery ──────────────────────────────────────────────

    #[test]
    fn query_new_defaults() {
        let q = SavedItemsQuery::new();
        assert_eq!(q.limit, 25);
        assert!(q.after.is_none());
        assert!(q.before.is_none());
        assert!(q.item_type_filter.is_none());
        assert!(q.subreddit_filter.is_none());
    }

    #[test]
    fn query_default_matches_new() {
        let q1 = SavedItemsQuery::new();
        let q2 = SavedItemsQuery::default();
        assert_eq!(q1.limit, q2.limit);
    }

    #[test]
    fn query_with_limit() {
        let q = SavedItemsQuery::new().with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn query_with_after() {
        let q = SavedItemsQuery::new().with_after("t3_abc");
        assert_eq!(q.after, Some("t3_abc".into()));
    }

    #[test]
    fn query_with_before() {
        let q = SavedItemsQuery::new().with_before("t3_xyz");
        assert_eq!(q.before, Some("t3_xyz".into()));
    }

    #[test]
    fn query_filter_type() {
        let q = SavedItemsQuery::new().filter_type(SavedItemType::Post);
        assert_eq!(q.item_type_filter, Some(SavedItemType::Post));
    }

    #[test]
    fn query_filter_subreddit() {
        let q = SavedItemsQuery::new().filter_subreddit("rust");
        assert_eq!(q.subreddit_filter, Some("rust".into()));
    }

    #[test]
    fn query_builder_chain() {
        let q = SavedItemsQuery::new()
            .with_limit(50)
            .with_after("cursor")
            .filter_type(SavedItemType::Comment)
            .filter_subreddit("programming");
        assert_eq!(q.limit, 50);
        assert_eq!(q.after, Some("cursor".into()));
        assert_eq!(q.item_type_filter, Some(SavedItemType::Comment));
        assert_eq!(q.subreddit_filter, Some("programming".into()));
    }

    #[test]
    fn query_validate_valid() {
        assert!(SavedItemsQuery::new().validate().is_ok());
    }

    #[test]
    fn query_validate_limit_zero() {
        let q = SavedItemsQuery::new().with_limit(0);
        assert!(q.validate().is_err());
    }

    #[test]
    fn query_validate_limit_over_max() {
        let q = SavedItemsQuery::new().with_limit(101);
        assert!(q.validate().is_err());
    }

    #[test]
    fn query_validate_limit_max_exactly() {
        let q = SavedItemsQuery::new().with_limit(100);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_limit_one() {
        let q = SavedItemsQuery::new().with_limit(1);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_serialize_roundtrip() {
        let q = SavedItemsQuery::new().with_limit(42).with_after("cur");
        let v = serde_json::to_value(&q).unwrap();
        let q2: SavedItemsQuery = serde_json::from_value(v).unwrap();
        assert_eq!(q2.limit, 42);
        assert_eq!(q2.after, Some("cur".into()));
    }

    #[test]
    fn query_clone() {
        let q = SavedItemsQuery::new().with_limit(10);
        #[allow(clippy::redundant_clone)]
        let q2 = q.clone();
        assert_eq!(q2.limit, 10);
    }

    #[test]
    fn query_debug() {
        let dbg = format!("{:?}", SavedItemsQuery::new());
        assert!(dbg.contains("limit"));
    }

    // ── SaveAction ───────────────────────────────────────────────────

    #[test]
    fn save_action_thing_id() {
        let a = SaveAction::Save {
            thing_id: "t3_abc".into(),
        };
        assert_eq!(a.thing_id(), "t3_abc");
    }

    #[test]
    fn unsave_action_thing_id() {
        let a = SaveAction::Unsave {
            thing_id: "t1_xyz".into(),
        };
        assert_eq!(a.thing_id(), "t1_xyz");
    }

    #[test]
    fn save_is_save() {
        let a = SaveAction::Save {
            thing_id: "t3_abc".into(),
        };
        assert!(a.is_save());
        assert!(!a.is_unsave());
    }

    #[test]
    fn unsave_is_unsave() {
        let a = SaveAction::Unsave {
            thing_id: "t1_abc".into(),
        };
        assert!(a.is_unsave());
        assert!(!a.is_save());
    }

    #[test]
    fn save_action_display() {
        let a = SaveAction::Save {
            thing_id: "t3_test".into(),
        };
        assert_eq!(a.to_string(), "save(t3_test)");
    }

    #[test]
    fn unsave_action_display() {
        let a = SaveAction::Unsave {
            thing_id: "t1_test".into(),
        };
        assert_eq!(a.to_string(), "unsave(t1_test)");
    }

    #[test]
    fn save_action_validate_valid_t3() {
        let a = SaveAction::Save {
            thing_id: "t3_abc123".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_validate_valid_t1() {
        let a = SaveAction::Unsave {
            thing_id: "t1_xyz".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_validate_valid_t2() {
        let a = SaveAction::Save {
            thing_id: "t2_account".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_validate_valid_t4() {
        let a = SaveAction::Save {
            thing_id: "t4_sub".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_validate_valid_t5() {
        let a = SaveAction::Save {
            thing_id: "t5_sub".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_validate_valid_t6() {
        let a = SaveAction::Save {
            thing_id: "t6_award".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_validate_empty_id() {
        let a = SaveAction::Save {
            thing_id: String::new(),
        };
        let err = a.validate().unwrap_err();
        assert!(matches!(err, SavedValidationError::EmptyThingId));
    }

    #[test]
    fn save_action_validate_no_prefix() {
        let a = SaveAction::Save {
            thing_id: "abc123".into(),
        };
        let err = a.validate().unwrap_err();
        assert!(matches!(err, SavedValidationError::InvalidThingId { .. }));
    }

    #[test]
    fn save_action_validate_bad_prefix() {
        let a = SaveAction::Save {
            thing_id: "t9_abc".into(),
        };
        let err = a.validate().unwrap_err();
        assert!(matches!(err, SavedValidationError::InvalidThingId { .. }));
    }

    #[test]
    fn save_action_validate_prefix_only() {
        let a = SaveAction::Save {
            thing_id: "t3_".into(),
        };
        let err = a.validate().unwrap_err();
        assert!(matches!(err, SavedValidationError::InvalidThingId { .. }));
    }

    #[test]
    fn save_action_validate_special_chars() {
        let a = SaveAction::Save {
            thing_id: "t3_abc!@#".into(),
        };
        let err = a.validate().unwrap_err();
        assert!(matches!(err, SavedValidationError::InvalidThingId { .. }));
    }

    #[test]
    fn save_action_validate_underscore_in_suffix() {
        let a = SaveAction::Save {
            thing_id: "t3_abc_123".into(),
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn save_action_serialize_roundtrip() {
        let a = SaveAction::Save {
            thing_id: "t3_ser".into(),
        };
        let v = serde_json::to_value(&a).unwrap();
        let a2: SaveAction = serde_json::from_value(v).unwrap();
        assert_eq!(a2.thing_id(), "t3_ser");
        assert!(a2.is_save());
    }

    #[test]
    fn unsave_action_serialize_roundtrip() {
        let a = SaveAction::Unsave {
            thing_id: "t1_ser".into(),
        };
        let v = serde_json::to_value(&a).unwrap();
        let a2: SaveAction = serde_json::from_value(v).unwrap();
        assert!(a2.is_unsave());
    }

    #[test]
    fn save_action_clone() {
        let a = SaveAction::Save {
            thing_id: "t3_cl".into(),
        };
        #[allow(clippy::redundant_clone)]
        let a2 = a.clone();
        assert_eq!(a2.thing_id(), "t3_cl");
    }

    #[test]
    fn save_action_debug() {
        let dbg = format!(
            "{:?}",
            SaveAction::Save {
                thing_id: "t3_dbg".into()
            }
        );
        assert!(dbg.contains("t3_dbg"));
    }

    // ── SaveResult ───────────────────────────────────────────────────

    #[test]
    fn save_result_success() {
        let action = SaveAction::Save {
            thing_id: "t3_ok".into(),
        };
        let result = SaveResult::success(action);
        assert!(result.success);
        assert_eq!(result.thing_id, "t3_ok");
        assert!(result.error_message.is_none());
    }

    #[test]
    fn save_result_failure() {
        let action = SaveAction::Unsave {
            thing_id: "t1_fail".into(),
        };
        let result = SaveResult::failure(action, "not found");
        assert!(!result.success);
        assert_eq!(result.thing_id, "t1_fail");
        assert_eq!(result.error_message, Some("not found".into()));
    }

    #[test]
    fn save_result_success_action_is_save() {
        let action = SaveAction::Save {
            thing_id: "t3_x".into(),
        };
        let result = SaveResult::success(action);
        assert!(result.action.is_save());
    }

    #[test]
    fn save_result_failure_action_is_unsave() {
        let action = SaveAction::Unsave {
            thing_id: "t1_x".into(),
        };
        let result = SaveResult::failure(action, "err");
        assert!(result.action.is_unsave());
    }

    #[test]
    fn save_result_serialize_roundtrip() {
        let result = SaveResult::success(SaveAction::Save {
            thing_id: "t3_ser".into(),
        });
        let v = serde_json::to_value(&result).unwrap();
        let result2: SaveResult = serde_json::from_value(v).unwrap();
        assert!(result2.success);
        assert_eq!(result2.thing_id, "t3_ser");
    }

    #[test]
    fn save_result_clone() {
        let result = SaveResult::success(SaveAction::Save {
            thing_id: "t3_cl".into(),
        });
        #[allow(clippy::redundant_clone)]
        let result2 = result.clone();
        assert_eq!(result2.thing_id, "t3_cl");
    }

    #[test]
    fn save_result_debug() {
        let dbg = format!(
            "{:?}",
            SaveResult::success(SaveAction::Save {
                thing_id: "t3_dbg".into()
            })
        );
        assert!(dbg.contains("t3_dbg"));
    }

    // ── SavedValidationError ─────────────────────────────────────────

    #[test]
    fn validation_error_invalid_limit_display() {
        let err = SavedValidationError::InvalidLimit {
            value: 200,
            max: 100,
        };
        let msg = err.to_string();
        assert!(msg.contains("200"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn validation_error_invalid_thing_id_display() {
        let err = SavedValidationError::InvalidThingId {
            value: "bad".into(),
            reason: "no prefix".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad"));
        assert!(msg.contains("no prefix"));
    }

    #[test]
    fn validation_error_empty_thing_id_display() {
        let err = SavedValidationError::EmptyThingId;
        let msg = err.to_string();
        assert!(msg.contains("empty"));
    }

    #[test]
    fn validation_error_is_std_error() {
        let err = SavedValidationError::EmptyThingId;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn validation_error_clone() {
        let err = SavedValidationError::EmptyThingId;
        #[allow(clippy::redundant_clone)]
        let err2 = err.clone();
        assert!(matches!(err2, SavedValidationError::EmptyThingId));
    }

    #[test]
    fn validation_error_debug() {
        let dbg = format!("{:?}", SavedValidationError::EmptyThingId);
        assert!(dbg.contains("EmptyThingId"));
    }

    #[test]
    fn validation_error_serialize_roundtrip() {
        let err = SavedValidationError::InvalidLimit { value: 0, max: 100 };
        let v = serde_json::to_value(&err).unwrap();
        let err2: SavedValidationError = serde_json::from_value(v).unwrap();
        assert!(matches!(
            err2,
            SavedValidationError::InvalidLimit { value: 0, max: 100 }
        ));
    }

    // ── SavedItemsValidator ──────────────────────────────────────────

    #[test]
    fn validator_new_defaults() {
        let v = SavedItemsValidator::new();
        assert_eq!(v.max_limit, 100);
        assert!(v.allowed_types.contains(&SavedItemType::Post));
        assert!(v.allowed_types.contains(&SavedItemType::Comment));
    }

    #[test]
    fn validator_default_matches_new() {
        let v1 = SavedItemsValidator::new();
        let v2 = SavedItemsValidator::default();
        assert_eq!(v1.max_limit, v2.max_limit);
        assert_eq!(v1.allowed_types.len(), v2.allowed_types.len());
    }

    #[test]
    fn validator_validate_query_valid() {
        let v = SavedItemsValidator::new();
        let q = SavedItemsQuery::new();
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_validate_query_zero_limit() {
        let v = SavedItemsValidator::new();
        let q = SavedItemsQuery::new().with_limit(0);
        assert!(v.validate_query(&q).is_err());
    }

    #[test]
    fn validator_validate_query_over_max() {
        let v = SavedItemsValidator::new();
        let q = SavedItemsQuery::new().with_limit(200);
        assert!(v.validate_query(&q).is_err());
    }

    #[test]
    fn validator_validate_query_custom_max() {
        let v = SavedItemsValidator {
            max_limit: 50,
            ..SavedItemsValidator::new()
        };
        let q = SavedItemsQuery::new().with_limit(51);
        assert!(v.validate_query(&q).is_err());
        let q2 = SavedItemsQuery::new().with_limit(50);
        assert!(v.validate_query(&q2).is_ok());
    }

    #[test]
    fn validator_validate_action_valid() {
        let v = SavedItemsValidator::new();
        let a = SaveAction::Save {
            thing_id: "t3_abc".into(),
        };
        assert!(v.validate_action(&a).is_ok());
    }

    #[test]
    fn validator_validate_action_invalid() {
        let v = SavedItemsValidator::new();
        let a = SaveAction::Save {
            thing_id: String::new(),
        };
        assert!(v.validate_action(&a).is_err());
    }

    #[test]
    fn validator_clone() {
        let v = SavedItemsValidator::new();
        #[allow(clippy::redundant_clone)]
        let v2 = v.clone();
        assert_eq!(v2.max_limit, 100);
    }

    #[test]
    fn validator_debug() {
        let dbg = format!("{:?}", SavedItemsValidator::new());
        assert!(dbg.contains("max_limit"));
    }

    // ── SavedItemsPolicy ─────────────────────────────────────────────

    #[test]
    fn policy_permissive() {
        let p = SavedItemsPolicy::new_permissive();
        assert!(p.allow_read);
        assert!(p.allow_save);
        assert!(p.allow_unsave);
    }

    #[test]
    fn policy_readonly() {
        let p = SavedItemsPolicy::new_readonly();
        assert!(p.allow_read);
        assert!(!p.allow_save);
        assert!(!p.allow_unsave);
    }

    #[test]
    fn policy_check_action_save_permissive() {
        let p = SavedItemsPolicy::new_permissive();
        let a = SaveAction::Save {
            thing_id: "t3_abc".into(),
        };
        assert!(p.check_action(&a));
    }

    #[test]
    fn policy_check_action_unsave_permissive() {
        let p = SavedItemsPolicy::new_permissive();
        let a = SaveAction::Unsave {
            thing_id: "t1_abc".into(),
        };
        assert!(p.check_action(&a));
    }

    #[test]
    fn policy_check_action_save_readonly() {
        let p = SavedItemsPolicy::new_readonly();
        let a = SaveAction::Save {
            thing_id: "t3_abc".into(),
        };
        assert!(!p.check_action(&a));
    }

    #[test]
    fn policy_check_action_unsave_readonly() {
        let p = SavedItemsPolicy::new_readonly();
        let a = SaveAction::Unsave {
            thing_id: "t1_abc".into(),
        };
        assert!(!p.check_action(&a));
    }

    #[test]
    fn policy_custom_save_only() {
        let p = SavedItemsPolicy {
            allow_read: true,
            allow_save: true,
            allow_unsave: false,
        };
        let save = SaveAction::Save {
            thing_id: "t3_x".into(),
        };
        let unsave = SaveAction::Unsave {
            thing_id: "t1_x".into(),
        };
        assert!(p.check_action(&save));
        assert!(!p.check_action(&unsave));
    }

    #[test]
    fn policy_custom_unsave_only() {
        let p = SavedItemsPolicy {
            allow_read: false,
            allow_save: false,
            allow_unsave: true,
        };
        let save = SaveAction::Save {
            thing_id: "t3_x".into(),
        };
        let unsave = SaveAction::Unsave {
            thing_id: "t1_x".into(),
        };
        assert!(!p.check_action(&save));
        assert!(p.check_action(&unsave));
    }

    #[test]
    fn policy_serialize_roundtrip() {
        let p = SavedItemsPolicy::new_permissive();
        let v = serde_json::to_value(&p).unwrap();
        let p2: SavedItemsPolicy = serde_json::from_value(v).unwrap();
        assert!(p2.allow_read);
        assert!(p2.allow_save);
        assert!(p2.allow_unsave);
    }

    #[test]
    fn policy_clone() {
        let p = SavedItemsPolicy::new_readonly();
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert!(p2.allow_read);
        assert!(!p2.allow_save);
    }

    #[test]
    fn policy_debug() {
        let dbg = format!("{:?}", SavedItemsPolicy::new_permissive());
        assert!(dbg.contains("allow_read"));
    }

    // ── SavedAuditEvent ──────────────────────────────────────────────

    #[test]
    fn audit_event_from_save_action() {
        let action = SaveAction::Save {
            thing_id: "t3_audit".into(),
        };
        let event = SavedAuditEvent::from_action(1_700_000_000.0, &action, true);
        assert_eq!(event.action_type, "save");
        assert_eq!(event.thing_id, Some("t3_audit".into()));
        assert!(event.was_allowed);
        assert!((event.timestamp - 1_700_000_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn audit_event_from_unsave_action() {
        let action = SaveAction::Unsave {
            thing_id: "t1_audit".into(),
        };
        let event = SavedAuditEvent::from_action(1_700_000_000.0, &action, false);
        assert_eq!(event.action_type, "unsave");
        assert_eq!(event.thing_id, Some("t1_audit".into()));
        assert!(!event.was_allowed);
    }

    #[test]
    fn audit_event_for_list() {
        let event = SavedAuditEvent::for_list(1_700_000_000.0, true);
        assert_eq!(event.action_type, "list");
        assert!(event.thing_id.is_none());
        assert!(event.was_allowed);
    }

    #[test]
    fn audit_event_for_list_denied() {
        let event = SavedAuditEvent::for_list(1_700_000_000.0, false);
        assert!(!event.was_allowed);
    }

    #[test]
    fn audit_event_serialize_roundtrip() {
        let event = SavedAuditEvent::for_list(1_700_000_000.0, true);
        let v = serde_json::to_value(&event).unwrap();
        let event2: SavedAuditEvent = serde_json::from_value(v).unwrap();
        assert_eq!(event2.action_type, "list");
        assert!(event2.was_allowed);
    }

    #[test]
    fn audit_event_clone() {
        let event = SavedAuditEvent::for_list(1_700_000_000.0, true);
        #[allow(clippy::redundant_clone)]
        let event2 = event.clone();
        assert_eq!(event2.action_type, "list");
    }

    #[test]
    fn audit_event_debug() {
        let dbg = format!("{:?}", SavedAuditEvent::for_list(1_700_000_000.0, true));
        assert!(dbg.contains("list"));
    }

    // ── make_body_preview ────────────────────────────────────────────

    #[test]
    fn body_preview_short_text() {
        let preview = make_body_preview("Hello, world!");
        assert_eq!(preview, "Hello, world!");
    }

    #[test]
    fn body_preview_exactly_200() {
        let text = "a".repeat(200);
        let preview = make_body_preview(&text);
        assert_eq!(preview.len(), 200);
        assert!(!preview.ends_with("..."));
    }

    #[test]
    fn body_preview_over_200() {
        let text = "b".repeat(300);
        let preview = make_body_preview(&text);
        assert!(preview.ends_with("..."));
        assert_eq!(preview.len(), 203); // 200 + "..."
    }

    #[test]
    fn body_preview_empty() {
        let preview = make_body_preview("");
        assert_eq!(preview, "");
    }

    #[test]
    fn body_preview_unicode() {
        // Each emoji is multi-byte but 1 char
        let text = "\u{1f600}".repeat(250);
        let preview = make_body_preview(&text);
        // Should have 200 emoji chars + "..."
        let char_count = preview.chars().count();
        assert_eq!(char_count, 203); // 200 emoji + 3 dots
    }

    // ── Integration / combined scenarios ─────────────────────────────

    #[test]
    fn policy_and_audit_combined() {
        let policy = SavedItemsPolicy::new_readonly();
        let action = SaveAction::Save {
            thing_id: "t3_denied".into(),
        };
        let allowed = policy.check_action(&action);
        let event = SavedAuditEvent::from_action(1_700_000_000.0, &action, allowed);
        assert!(!event.was_allowed);
        assert_eq!(event.action_type, "save");
    }

    #[test]
    fn validator_and_query_combined() {
        let validator = SavedItemsValidator::new();
        let query = SavedItemsQuery::new().with_limit(50).with_after("cursor");
        assert!(validator.validate_query(&query).is_ok());
    }

    #[test]
    fn validator_and_action_combined() {
        let validator = SavedItemsValidator::new();
        let action = SaveAction::Save {
            thing_id: "t3_combined".into(),
        };
        assert!(validator.validate_action(&action).is_ok());
    }

    #[test]
    fn full_flow_save_success() {
        let policy = SavedItemsPolicy::new_permissive();
        let validator = SavedItemsValidator::new();
        let action = SaveAction::Save {
            thing_id: "t3_flow".into(),
        };

        assert!(policy.check_action(&action));
        assert!(validator.validate_action(&action).is_ok());
        let result = SaveResult::success(action);
        assert!(result.success);
    }

    #[test]
    fn full_flow_unsave_denied() {
        let policy = SavedItemsPolicy::new_readonly();
        let action = SaveAction::Unsave {
            thing_id: "t1_flow".into(),
        };

        assert!(!policy.check_action(&action));
        let event = SavedAuditEvent::from_action(1_700_000_000.0, &action, false);
        assert!(!event.was_allowed);
    }

    #[test]
    fn full_flow_invalid_action_rejected() {
        let validator = SavedItemsValidator::new();
        let action = SaveAction::Save {
            thing_id: "invalid_no_prefix".into(),
        };
        assert!(validator.validate_action(&action).is_err());
    }

    #[test]
    fn page_filtering_scenario() {
        let page = SavedItemsPage {
            items: vec![
                sample_post(),
                sample_comment(),
                sample_post(),
                sample_comment(),
            ],
            after: Some("next".into()),
            before: None,
            count: 4,
            has_more: true,
        };
        assert_eq!(page.post_count(), 2);
        assert_eq!(page.comment_count(), 2);
        assert_eq!(page.len(), 4);

        assert!(
            page.items_of_type(SavedItemType::Post)
                .all(SavedItem::is_post)
        );
    }

    #[test]
    fn query_validation_error_message() {
        let q = SavedItemsQuery::new().with_limit(0);
        let err = q.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid limit"));
        assert!(msg.contains('0'));
    }

    #[test]
    fn save_action_validate_t7_invalid() {
        let a = SaveAction::Save {
            thing_id: "t7_abc".into(),
        };
        assert!(a.validate().is_err());
    }

    #[test]
    fn save_action_validate_spaces_invalid() {
        let a = SaveAction::Save {
            thing_id: "t3_abc def".into(),
        };
        assert!(a.validate().is_err());
    }

    #[test]
    fn saved_item_long_preview() {
        let mut item = sample_comment();
        item.body_preview = Some("x".repeat(1000));
        let preview = item.truncated_preview(100).unwrap();
        assert_eq!(preview.len(), 103); // 100 + "..."
    }

    #[test]
    fn saved_item_truncated_preview_exact_len() {
        let mut item = sample_comment();
        item.body_preview = Some("exact".into());
        let preview = item.truncated_preview(5).unwrap();
        assert_eq!(preview, "exact");
    }

    #[test]
    fn saved_item_truncated_preview_one_over() {
        let mut item = sample_comment();
        item.body_preview = Some("abcdef".into());
        let preview = item.truncated_preview(5).unwrap();
        assert_eq!(preview, "abcde...");
    }

    #[test]
    fn page_all_posts() {
        let page = SavedItemsPage {
            items: vec![sample_post(), sample_post()],
            after: None,
            before: None,
            count: 2,
            has_more: false,
        };
        assert_eq!(page.post_count(), 2);
        assert_eq!(page.comment_count(), 0);
    }

    #[test]
    fn page_all_comments() {
        let page = SavedItemsPage {
            items: vec![sample_comment(), sample_comment()],
            after: None,
            before: None,
            count: 2,
            has_more: false,
        };
        assert_eq!(page.post_count(), 0);
        assert_eq!(page.comment_count(), 2);
    }

    #[test]
    fn validation_error_invalid_limit_clone() {
        let err = SavedValidationError::InvalidLimit {
            value: 999,
            max: 100,
        };
        #[allow(clippy::redundant_clone)]
        let err2 = err.clone();
        assert!(matches!(
            err2,
            SavedValidationError::InvalidLimit {
                value: 999,
                max: 100
            }
        ));
    }

    #[test]
    fn validation_error_invalid_thing_id_clone() {
        let err = SavedValidationError::InvalidThingId {
            value: "x".into(),
            reason: "bad".into(),
        };
        #[allow(clippy::redundant_clone)]
        let err2 = err.clone();
        assert!(matches!(err2, SavedValidationError::InvalidThingId { .. }));
    }
}
