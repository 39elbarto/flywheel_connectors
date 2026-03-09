//! `Reddit` user posting and commenting module.
//!
//! Provides controlled `Reddit` participation: submit posts, comments, edit/delete
//! own content. These are real-world side effects — tightly capability-scoped and
//! dangerous operations requiring approval.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Post Kind ────────────────────────────────────────────────────────

/// The kind of `Reddit` post being submitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostKind {
    /// Text/self post.
    Text,
    /// Link post.
    Link,
    /// Image post.
    Image,
    /// Video post.
    Video,
    /// Poll post.
    Poll,
    /// Crosspost from another post.
    Crosspost,
}

impl PostKind {
    /// Returns the `Reddit` API string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "self",
            Self::Link => "link",
            Self::Image => "image",
            Self::Video => "video",
            Self::Poll => "poll",
            Self::Crosspost => "crosspost",
        }
    }
}

impl fmt::Display for PostKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Validation Error ─────────────────────────────────────────────────

/// Validation errors for `Reddit` posting operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostingValidationError {
    /// Title is empty.
    EmptyTitle,
    /// Title exceeds maximum length.
    TitleTooLong { length: usize, max: usize },
    /// Body text is empty.
    EmptyBody,
    /// Body exceeds maximum length.
    BodyTooLong { length: usize, max: usize },
    /// Parent ID has invalid format (must be `t1_` or `t3_`).
    InvalidParentId { id: String },
    /// Thing ID has invalid format.
    InvalidThingId { id: String },
    /// URL is required for link posts but was not provided.
    MissingUrl,
    /// The target subreddit is blocked by policy.
    BlockedSubreddit { subreddit: String },
}

impl fmt::Display for PostingValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTitle => write!(f, "Post title must not be empty"),
            Self::TitleTooLong { length, max } => {
                write!(f, "Post title too long ({length} chars, max {max})")
            }
            Self::EmptyBody => write!(f, "Body text must not be empty"),
            Self::BodyTooLong { length, max } => {
                write!(f, "Body too long ({length} chars, max {max})")
            }
            Self::InvalidParentId { id } => {
                write!(f, "Invalid parent ID format: {id} (expected t1_ or t3_ prefix)")
            }
            Self::InvalidThingId { id } => {
                write!(f, "Invalid thing ID format: {id} (expected t1_ or t3_ prefix)")
            }
            Self::MissingUrl => write!(f, "URL is required for link posts"),
            Self::BlockedSubreddit { subreddit } => {
                write!(f, "Subreddit r/{subreddit} is blocked by policy")
            }
        }
    }
}

impl std::error::Error for PostingValidationError {}

// ── Submit Post Request ──────────────────────────────────────────────

/// Request to submit a new `Reddit` post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPostRequest {
    /// Target subreddit name (without `r/` prefix).
    pub subreddit: String,
    /// Post title.
    pub title: String,
    /// The kind of post.
    pub post_kind: PostKind,
    /// Body text (required for text posts).
    pub body: Option<String>,
    /// URL (required for link posts).
    pub url: Option<String>,
    /// Whether the post is NSFW.
    pub nsfw: bool,
    /// Whether the post is a spoiler.
    pub spoiler: bool,
    /// Optional flair ID.
    pub flair_id: Option<String>,
    /// Whether to receive reply notifications.
    pub send_replies: bool,
}

impl SubmitPostRequest {
    /// Validates the post request using the given validator.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if validation fails.
    pub fn validate(&self, validator: &PostingValidator) -> Result<(), PostingValidationError> {
        validator.validate_post(self)
    }
}

// ── Submit Comment Request ───────────────────────────────────────────

/// Request to submit a comment on a `Reddit` post or reply to a comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitCommentRequest {
    /// The fullname of the parent (e.g. `t3_abc` for a post, `t1_xyz` for a comment).
    pub parent_id: String,
    /// Comment body text (Markdown).
    pub body: String,
}

impl SubmitCommentRequest {
    /// Validates the comment request using the given validator.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if validation fails.
    pub fn validate(&self, validator: &PostingValidator) -> Result<(), PostingValidationError> {
        validator.validate_comment(self)
    }
}

// ── Edit Request ─────────────────────────────────────────────────────

/// Request to edit an existing `Reddit` post or comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRequest {
    /// The fullname of the thing to edit (e.g. `t1_xyz` or `t3_abc`).
    pub thing_id: String,
    /// The new body text.
    pub new_body: String,
}

impl EditRequest {
    /// Validates the edit request using the given validator.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if validation fails.
    pub fn validate(&self, validator: &PostingValidator) -> Result<(), PostingValidationError> {
        validator.validate_edit(self)
    }
}

// ── Delete Request ───────────────────────────────────────────────────

/// Request to delete an existing `Reddit` post or comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    /// The fullname of the thing to delete (e.g. `t1_xyz` or `t3_abc`).
    pub thing_id: String,
}

impl DeleteRequest {
    /// Validates the delete request.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if the thing ID format is invalid.
    pub fn validate(&self) -> Result<(), PostingValidationError> {
        validate_thing_id(&self.thing_id)
    }
}

// ── Submit Result ────────────────────────────────────────────────────

/// Result of a successful `Reddit` post or comment submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResult {
    /// The short ID of the created thing.
    pub id: String,
    /// The fullname of the created thing (e.g. `t3_abc123`).
    pub fullname: String,
    /// The URL of the created thing.
    pub url: String,
    /// Whether the submission was successful.
    pub success: bool,
}

// ── Posting Decision ─────────────────────────────────────────────────

/// Decision from a `PostingPolicy` check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostingDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
    },
    /// The operation requires manual approval.
    RequireApproval {
        /// Human-readable reason for requiring approval.
        reason: String,
    },
}

impl PostingDecision {
    /// Returns `true` if the decision allows the operation.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision denies the operation.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns `true` if the decision requires approval.
    #[must_use]
    pub const fn is_approval_required(&self) -> bool {
        matches!(self, Self::RequireApproval { .. })
    }
}

// ── Posting Policy ───────────────────────────────────────────────────

/// Policy controlling what `Reddit` posting operations are allowed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostingPolicy {
    /// Whether posting new submissions is allowed.
    pub allow_post: bool,
    /// Whether commenting is allowed.
    pub allow_comment: bool,
    /// Whether editing own content is allowed.
    pub allow_edit: bool,
    /// Whether deleting own content is allowed.
    pub allow_delete: bool,
    /// Whether posting requires approval.
    pub require_approval_for_post: bool,
    /// Whether deleting requires approval.
    pub require_approval_for_delete: bool,
    /// Maximum post body length.
    pub max_post_length: usize,
    /// Maximum comment body length.
    pub max_comment_length: usize,
    /// Subreddits that are blocked from posting/commenting.
    pub blocked_subreddits: HashSet<String>,
    /// Minimum seconds between actions (rate limiting).
    pub rate_limit_seconds: u32,
}

impl PostingPolicy {
    /// Creates a permissive policy allowing all operations.
    #[must_use]
    pub fn new_permissive() -> Self {
        Self {
            allow_post: true,
            allow_comment: true,
            allow_edit: true,
            allow_delete: true,
            require_approval_for_post: false,
            require_approval_for_delete: false,
            max_post_length: 40_000,
            max_comment_length: 10_000,
            blocked_subreddits: HashSet::new(),
            rate_limit_seconds: 0,
        }
    }

    /// Creates a read-only policy that denies all write operations.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_post: false,
            allow_comment: false,
            allow_edit: false,
            allow_delete: false,
            require_approval_for_post: false,
            require_approval_for_delete: false,
            max_post_length: 40_000,
            max_comment_length: 10_000,
            blocked_subreddits: HashSet::new(),
            rate_limit_seconds: 0,
        }
    }

    /// Checks whether a post submission is allowed under this policy.
    #[must_use]
    pub fn check_post(&self, subreddit: &str) -> PostingDecision {
        if !self.allow_post {
            return PostingDecision::Deny {
                reason: "Posting is disabled by policy".into(),
            };
        }
        let sub_lower = subreddit.to_lowercase();
        if self.blocked_subreddits.contains(&sub_lower) {
            return PostingDecision::Deny {
                reason: format!("Subreddit r/{subreddit} is blocked by policy"),
            };
        }
        if self.require_approval_for_post {
            return PostingDecision::RequireApproval {
                reason: "Post submission requires approval".into(),
            };
        }
        PostingDecision::Allow
    }

    /// Checks whether commenting is allowed under this policy.
    #[must_use]
    pub fn check_comment(&self) -> PostingDecision {
        if !self.allow_comment {
            return PostingDecision::Deny {
                reason: "Commenting is disabled by policy".into(),
            };
        }
        PostingDecision::Allow
    }

    /// Checks whether editing is allowed under this policy.
    #[must_use]
    pub fn check_edit(&self) -> PostingDecision {
        if !self.allow_edit {
            return PostingDecision::Deny {
                reason: "Editing is disabled by policy".into(),
            };
        }
        PostingDecision::Allow
    }

    /// Checks whether deleting is allowed under this policy.
    #[must_use]
    pub fn check_delete(&self) -> PostingDecision {
        if !self.allow_delete {
            return PostingDecision::Deny {
                reason: "Deleting is disabled by policy".into(),
            };
        }
        if self.require_approval_for_delete {
            return PostingDecision::RequireApproval {
                reason: "Deletion requires approval".into(),
            };
        }
        PostingDecision::Allow
    }
}

// ── Posting Validator ────────────────────────────────────────────────

/// Validates `Reddit` posting requests against size limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostingValidator {
    /// Maximum title length in characters.
    pub max_title_length: usize,
    /// Maximum post body length in characters.
    pub max_body_length: usize,
    /// Maximum comment body length in characters.
    pub max_comment_length: usize,
}

impl Default for PostingValidator {
    fn default() -> Self {
        Self {
            max_title_length: 300,
            max_body_length: 40_000,
            max_comment_length: 10_000,
        }
    }
}

impl PostingValidator {
    /// Validates a post submission request.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if the request is invalid.
    pub fn validate_post(&self, req: &SubmitPostRequest) -> Result<(), PostingValidationError> {
        if req.title.trim().is_empty() {
            return Err(PostingValidationError::EmptyTitle);
        }
        if req.title.len() > self.max_title_length {
            return Err(PostingValidationError::TitleTooLong {
                length: req.title.len(),
                max: self.max_title_length,
            });
        }
        match req.post_kind {
            PostKind::Text => {
                if let Some(body) = &req.body {
                    if body.len() > self.max_body_length {
                        return Err(PostingValidationError::BodyTooLong {
                            length: body.len(),
                            max: self.max_body_length,
                        });
                    }
                }
            }
            PostKind::Link | PostKind::Image | PostKind::Video => {
                if req.url.is_none() || req.url.as_deref().is_some_and(|u| u.trim().is_empty()) {
                    return Err(PostingValidationError::MissingUrl);
                }
            }
            PostKind::Poll | PostKind::Crosspost => {}
        }
        Ok(())
    }

    /// Validates a comment submission request.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if the request is invalid.
    pub fn validate_comment(
        &self,
        req: &SubmitCommentRequest,
    ) -> Result<(), PostingValidationError> {
        if req.body.trim().is_empty() {
            return Err(PostingValidationError::EmptyBody);
        }
        if req.body.len() > self.max_comment_length {
            return Err(PostingValidationError::BodyTooLong {
                length: req.body.len(),
                max: self.max_comment_length,
            });
        }
        validate_parent_id(&req.parent_id)?;
        Ok(())
    }

    /// Validates an edit request.
    ///
    /// # Errors
    ///
    /// Returns a `PostingValidationError` if the request is invalid.
    pub fn validate_edit(&self, req: &EditRequest) -> Result<(), PostingValidationError> {
        if req.new_body.trim().is_empty() {
            return Err(PostingValidationError::EmptyBody);
        }
        if req.new_body.len() > self.max_body_length {
            return Err(PostingValidationError::BodyTooLong {
                length: req.new_body.len(),
                max: self.max_body_length,
            });
        }
        validate_thing_id(&req.thing_id)?;
        Ok(())
    }
}

// ── Posting Action ───────────────────────────────────────────────────

/// The kind of posting action being audited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostingAction {
    /// Submitting a new post.
    Post,
    /// Submitting a comment.
    Comment,
    /// Editing existing content.
    Edit,
    /// Deleting existing content.
    Delete,
}

impl fmt::Display for PostingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Post => write!(f, "post"),
            Self::Comment => write!(f, "comment"),
            Self::Edit => write!(f, "edit"),
            Self::Delete => write!(f, "delete"),
        }
    }
}

// ── Posting Audit Event ──────────────────────────────────────────────

/// Audit log entry for a `Reddit` posting operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostingAuditEvent {
    /// Timestamp of the event (Unix epoch seconds).
    pub timestamp: u64,
    /// The action performed.
    pub action: PostingAction,
    /// The fullname of the thing involved, if applicable.
    pub thing_id: Option<String>,
    /// The target subreddit, if applicable.
    pub subreddit: Option<String>,
    /// Length of the content submitted/edited.
    pub content_length: usize,
    /// Whether the action was allowed.
    pub was_allowed: bool,
}

impl PostingAuditEvent {
    /// Creates a new audit event.
    #[must_use]
    pub const fn new(
        timestamp: u64,
        action: PostingAction,
        thing_id: Option<String>,
        subreddit: Option<String>,
        content_length: usize,
        was_allowed: bool,
    ) -> Self {
        Self {
            timestamp,
            action,
            thing_id,
            subreddit,
            content_length,
            was_allowed,
        }
    }

    /// Creates a post submission audit event.
    #[must_use]
    pub fn for_post(timestamp: u64, subreddit: &str, content_length: usize, allowed: bool) -> Self {
        Self {
            timestamp,
            action: PostingAction::Post,
            thing_id: None,
            subreddit: Some(subreddit.to_owned()),
            content_length,
            was_allowed: allowed,
        }
    }

    /// Creates a comment submission audit event.
    #[must_use]
    pub fn for_comment(
        timestamp: u64,
        parent_id: &str,
        content_length: usize,
        allowed: bool,
    ) -> Self {
        Self {
            timestamp,
            action: PostingAction::Comment,
            thing_id: Some(parent_id.to_owned()),
            subreddit: None,
            content_length,
            was_allowed: allowed,
        }
    }

    /// Creates an edit audit event.
    #[must_use]
    pub fn for_edit(
        timestamp: u64,
        thing_id: &str,
        content_length: usize,
        allowed: bool,
    ) -> Self {
        Self {
            timestamp,
            action: PostingAction::Edit,
            thing_id: Some(thing_id.to_owned()),
            subreddit: None,
            content_length,
            was_allowed: allowed,
        }
    }

    /// Creates a delete audit event.
    #[must_use]
    pub fn for_delete(timestamp: u64, thing_id: &str, allowed: bool) -> Self {
        Self {
            timestamp,
            action: PostingAction::Delete,
            thing_id: Some(thing_id.to_owned()),
            subreddit: None,
            content_length: 0,
            was_allowed: allowed,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Validates a `Reddit` fullname parent ID (must start with `t1_` or `t3_`).
fn validate_parent_id(id: &str) -> Result<(), PostingValidationError> {
    if id.starts_with("t1_") || id.starts_with("t3_") {
        if id.len() <= 3 {
            return Err(PostingValidationError::InvalidParentId { id: id.to_owned() });
        }
        Ok(())
    } else {
        Err(PostingValidationError::InvalidParentId { id: id.to_owned() })
    }
}

/// Validates a `Reddit` fullname thing ID (must start with `t1_` or `t3_`).
fn validate_thing_id(id: &str) -> Result<(), PostingValidationError> {
    if id.starts_with("t1_") || id.starts_with("t3_") {
        if id.len() <= 3 {
            return Err(PostingValidationError::InvalidThingId { id: id.to_owned() });
        }
        Ok(())
    } else {
        Err(PostingValidationError::InvalidThingId { id: id.to_owned() })
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_validator() -> PostingValidator {
        PostingValidator::default()
    }

    fn text_post(subreddit: &str, title: &str, body: Option<&str>) -> SubmitPostRequest {
        SubmitPostRequest {
            subreddit: subreddit.into(),
            title: title.into(),
            post_kind: PostKind::Text,
            body: body.map(Into::into),
            url: None,
            nsfw: false,
            spoiler: false,
            flair_id: None,
            send_replies: true,
        }
    }

    fn link_post(subreddit: &str, title: &str, url: Option<&str>) -> SubmitPostRequest {
        SubmitPostRequest {
            subreddit: subreddit.into(),
            title: title.into(),
            post_kind: PostKind::Link,
            body: None,
            url: url.map(Into::into),
            nsfw: false,
            spoiler: false,
            flair_id: None,
            send_replies: true,
        }
    }

    // ── PostKind ─────────────────────────────────────────────────────

    #[test]
    fn post_kind_as_str_text() {
        assert_eq!(PostKind::Text.as_str(), "self");
    }

    #[test]
    fn post_kind_as_str_link() {
        assert_eq!(PostKind::Link.as_str(), "link");
    }

    #[test]
    fn post_kind_as_str_image() {
        assert_eq!(PostKind::Image.as_str(), "image");
    }

    #[test]
    fn post_kind_as_str_video() {
        assert_eq!(PostKind::Video.as_str(), "video");
    }

    #[test]
    fn post_kind_as_str_poll() {
        assert_eq!(PostKind::Poll.as_str(), "poll");
    }

    #[test]
    fn post_kind_as_str_crosspost() {
        assert_eq!(PostKind::Crosspost.as_str(), "crosspost");
    }

    #[test]
    fn post_kind_display() {
        assert_eq!(PostKind::Text.to_string(), "self");
        assert_eq!(PostKind::Link.to_string(), "link");
    }

    #[test]
    fn post_kind_eq() {
        assert_eq!(PostKind::Text, PostKind::Text);
        assert_ne!(PostKind::Text, PostKind::Link);
    }

    #[test]
    fn post_kind_clone() {
        let k = PostKind::Image;
        #[allow(clippy::redundant_clone)]
        let k2 = k.clone();
        assert_eq!(k2, PostKind::Image);
    }

    #[test]
    fn post_kind_debug() {
        let dbg = format!("{:?}", PostKind::Poll);
        assert!(dbg.contains("Poll"));
    }

    #[test]
    fn post_kind_serialize() {
        let v = serde_json::to_value(&PostKind::Video).unwrap();
        assert_eq!(v, "Video");
    }

    #[test]
    fn post_kind_deserialize() {
        let k: PostKind = serde_json::from_str("\"Crosspost\"").unwrap();
        assert_eq!(k, PostKind::Crosspost);
    }

    #[test]
    fn post_kind_roundtrip_all() {
        for kind in [
            PostKind::Text,
            PostKind::Link,
            PostKind::Image,
            PostKind::Video,
            PostKind::Poll,
            PostKind::Crosspost,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PostKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // ── SubmitPostRequest validation ─────────────────────────────────

    #[test]
    fn valid_text_post() {
        let req = text_post("rust", "Hello World", Some("body text"));
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn valid_text_post_no_body() {
        let req = text_post("rust", "Title Only", None);
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn empty_title_rejected() {
        let req = text_post("rust", "", Some("body"));
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::EmptyTitle
        );
    }

    #[test]
    fn whitespace_only_title_rejected() {
        let req = text_post("rust", "   \t\n  ", Some("body"));
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::EmptyTitle
        );
    }

    #[test]
    fn title_too_long_rejected() {
        let long_title = "a".repeat(301);
        let req = text_post("rust", &long_title, Some("body"));
        match req.validate(&default_validator()).unwrap_err() {
            PostingValidationError::TitleTooLong { length, max } => {
                assert_eq!(length, 301);
                assert_eq!(max, 300);
            }
            other => panic!("expected TitleTooLong, got {other:?}"),
        }
    }

    #[test]
    fn title_exactly_max_length_ok() {
        let title = "a".repeat(300);
        let req = text_post("rust", &title, Some("body"));
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn text_post_body_too_long() {
        let long_body = "x".repeat(40_001);
        let req = text_post("rust", "Title", Some(&long_body));
        match req.validate(&default_validator()).unwrap_err() {
            PostingValidationError::BodyTooLong { length, max } => {
                assert_eq!(length, 40_001);
                assert_eq!(max, 40_000);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    #[test]
    fn text_post_body_exactly_max_ok() {
        let body = "x".repeat(40_000);
        let req = text_post("rust", "Title", Some(&body));
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn link_post_valid() {
        let req = link_post("rust", "Check this out", Some("https://example.com"));
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn link_post_missing_url() {
        let req = link_post("rust", "Check this out", None);
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::MissingUrl
        );
    }

    #[test]
    fn link_post_empty_url() {
        let req = link_post("rust", "Title", Some(""));
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::MissingUrl
        );
    }

    #[test]
    fn link_post_whitespace_url() {
        let req = link_post("rust", "Title", Some("   "));
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::MissingUrl
        );
    }

    #[test]
    fn image_post_missing_url() {
        let mut req = text_post("rust", "Image post", None);
        req.post_kind = PostKind::Image;
        req.url = None;
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::MissingUrl
        );
    }

    #[test]
    fn image_post_valid() {
        let mut req = text_post("rust", "Image post", None);
        req.post_kind = PostKind::Image;
        req.url = Some("https://i.imgur.com/test.png".into());
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn video_post_missing_url() {
        let mut req = text_post("rust", "Video post", None);
        req.post_kind = PostKind::Video;
        req.url = None;
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::MissingUrl
        );
    }

    #[test]
    fn video_post_valid() {
        let mut req = text_post("rust", "Video post", None);
        req.post_kind = PostKind::Video;
        req.url = Some("https://v.redd.it/test".into());
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn poll_post_no_url_required() {
        let mut req = text_post("rust", "Poll post", None);
        req.post_kind = PostKind::Poll;
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn crosspost_no_url_required() {
        let mut req = text_post("rust", "Crosspost", None);
        req.post_kind = PostKind::Crosspost;
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn post_nsfw_flag() {
        let mut req = text_post("rust", "NSFW test", Some("body"));
        req.nsfw = true;
        assert!(req.nsfw);
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn post_spoiler_flag() {
        let mut req = text_post("rust", "Spoiler test", Some("body"));
        req.spoiler = true;
        assert!(req.spoiler);
    }

    #[test]
    fn post_flair_id() {
        let mut req = text_post("rust", "Flair test", Some("body"));
        req.flair_id = Some("abc123".into());
        assert_eq!(req.flair_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn post_send_replies_default_true() {
        let req = text_post("rust", "Reply test", None);
        assert!(req.send_replies);
    }

    #[test]
    fn submit_post_request_debug() {
        let req = text_post("rust", "Debug test", Some("body"));
        let dbg = format!("{req:?}");
        assert!(dbg.contains("Debug test"));
    }

    #[test]
    fn submit_post_request_clone() {
        let req = text_post("rust", "Clone test", Some("body"));
        #[allow(clippy::redundant_clone)]
        let req2 = req.clone();
        assert_eq!(req2.title, "Clone test");
    }

    #[test]
    fn submit_post_request_serialize() {
        let req = text_post("rust", "Serde test", Some("body"));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Serde test"));
    }

    #[test]
    fn submit_post_request_deserialize() {
        let req = text_post("rust", "Deser test", Some("body"));
        let json = serde_json::to_string(&req).unwrap();
        let back: SubmitPostRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, "Deser test");
        assert_eq!(back.subreddit, "rust");
    }

    // ── Custom validator limits ──────────────────────────────────────

    #[test]
    fn custom_max_title_length() {
        let v = PostingValidator {
            max_title_length: 10,
            ..Default::default()
        };
        let req = text_post("rust", "Short", Some("body"));
        assert!(req.validate(&v).is_ok());

        let req = text_post("rust", "This title is way too long", Some("body"));
        assert!(req.validate(&v).is_err());
    }

    #[test]
    fn custom_max_body_length() {
        let v = PostingValidator {
            max_body_length: 50,
            ..Default::default()
        };
        let req = text_post("rust", "Title", Some(&"x".repeat(51)));
        match req.validate(&v).unwrap_err() {
            PostingValidationError::BodyTooLong { length, max } => {
                assert_eq!(length, 51);
                assert_eq!(max, 50);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    #[test]
    fn custom_max_comment_length() {
        let v = PostingValidator {
            max_comment_length: 20,
            ..Default::default()
        };
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: "x".repeat(21),
        };
        match req.validate(&v).unwrap_err() {
            PostingValidationError::BodyTooLong { length, max } => {
                assert_eq!(length, 21);
                assert_eq!(max, 20);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    // ── SubmitCommentRequest validation ──────────────────────────────

    #[test]
    fn valid_comment_on_post() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc123".into(),
            body: "Great post!".into(),
        };
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn valid_comment_reply() {
        let req = SubmitCommentRequest {
            parent_id: "t1_xyz789".into(),
            body: "Thanks!".into(),
        };
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn comment_empty_body() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: String::new(),
        };
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::EmptyBody
        );
    }

    #[test]
    fn comment_whitespace_body() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: "  \n\t  ".into(),
        };
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::EmptyBody
        );
    }

    #[test]
    fn comment_body_too_long() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: "x".repeat(10_001),
        };
        match req.validate(&default_validator()).unwrap_err() {
            PostingValidationError::BodyTooLong { length, max } => {
                assert_eq!(length, 10_001);
                assert_eq!(max, 10_000);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    #[test]
    fn comment_body_exactly_max_ok() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: "x".repeat(10_000),
        };
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn comment_invalid_parent_id_no_prefix() {
        let req = SubmitCommentRequest {
            parent_id: "abc123".into(),
            body: "Hello".into(),
        };
        match req.validate(&default_validator()).unwrap_err() {
            PostingValidationError::InvalidParentId { id } => {
                assert_eq!(id, "abc123");
            }
            other => panic!("expected InvalidParentId, got {other:?}"),
        }
    }

    #[test]
    fn comment_invalid_parent_id_wrong_type() {
        let req = SubmitCommentRequest {
            parent_id: "t2_user".into(),
            body: "Hello".into(),
        };
        assert!(matches!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::InvalidParentId { .. }
        ));
    }

    #[test]
    fn comment_invalid_parent_id_t5() {
        let req = SubmitCommentRequest {
            parent_id: "t5_sub".into(),
            body: "Hello".into(),
        };
        assert!(matches!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::InvalidParentId { .. }
        ));
    }

    #[test]
    fn comment_invalid_parent_id_empty() {
        let req = SubmitCommentRequest {
            parent_id: String::new(),
            body: "Hello".into(),
        };
        assert!(matches!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::InvalidParentId { .. }
        ));
    }

    #[test]
    fn comment_invalid_parent_id_prefix_only() {
        let req = SubmitCommentRequest {
            parent_id: "t3_".into(),
            body: "Hello".into(),
        };
        assert!(matches!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::InvalidParentId { .. }
        ));
    }

    #[test]
    fn submit_comment_debug() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: "dbg".into(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("t3_abc"));
    }

    #[test]
    fn submit_comment_clone() {
        let req = SubmitCommentRequest {
            parent_id: "t3_abc".into(),
            body: "clone".into(),
        };
        #[allow(clippy::redundant_clone)]
        let req2 = req.clone();
        assert_eq!(req2.body, "clone");
    }

    #[test]
    fn submit_comment_serialize_roundtrip() {
        let req = SubmitCommentRequest {
            parent_id: "t1_xyz".into(),
            body: "serde test".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SubmitCommentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parent_id, "t1_xyz");
        assert_eq!(back.body, "serde test");
    }

    // ── EditRequest validation ───────────────────────────────────────

    #[test]
    fn valid_edit_post() {
        let req = EditRequest {
            thing_id: "t3_abc123".into(),
            new_body: "Updated body".into(),
        };
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn valid_edit_comment() {
        let req = EditRequest {
            thing_id: "t1_xyz789".into(),
            new_body: "Fixed typo".into(),
        };
        assert!(req.validate(&default_validator()).is_ok());
    }

    #[test]
    fn edit_empty_body() {
        let req = EditRequest {
            thing_id: "t3_abc".into(),
            new_body: String::new(),
        };
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::EmptyBody
        );
    }

    #[test]
    fn edit_whitespace_body() {
        let req = EditRequest {
            thing_id: "t3_abc".into(),
            new_body: "  \t  ".into(),
        };
        assert_eq!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::EmptyBody
        );
    }

    #[test]
    fn edit_body_too_long() {
        let req = EditRequest {
            thing_id: "t3_abc".into(),
            new_body: "x".repeat(40_001),
        };
        match req.validate(&default_validator()).unwrap_err() {
            PostingValidationError::BodyTooLong { length, max } => {
                assert_eq!(length, 40_001);
                assert_eq!(max, 40_000);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    #[test]
    fn edit_invalid_thing_id() {
        let req = EditRequest {
            thing_id: "invalid".into(),
            new_body: "body".into(),
        };
        match req.validate(&default_validator()).unwrap_err() {
            PostingValidationError::InvalidThingId { id } => {
                assert_eq!(id, "invalid");
            }
            other => panic!("expected InvalidThingId, got {other:?}"),
        }
    }

    #[test]
    fn edit_thing_id_wrong_type() {
        let req = EditRequest {
            thing_id: "t2_user".into(),
            new_body: "body".into(),
        };
        assert!(matches!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn edit_thing_id_prefix_only() {
        let req = EditRequest {
            thing_id: "t1_".into(),
            new_body: "body".into(),
        };
        assert!(matches!(
            req.validate(&default_validator()).unwrap_err(),
            PostingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn edit_request_debug() {
        let req = EditRequest {
            thing_id: "t3_dbg".into(),
            new_body: "debug".into(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn edit_request_clone() {
        let req = EditRequest {
            thing_id: "t3_cl".into(),
            new_body: "clone".into(),
        };
        #[allow(clippy::redundant_clone)]
        let req2 = req.clone();
        assert_eq!(req2.thing_id, "t3_cl");
    }

    #[test]
    fn edit_request_serialize_roundtrip() {
        let req = EditRequest {
            thing_id: "t1_ser".into(),
            new_body: "serde body".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: EditRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thing_id, "t1_ser");
        assert_eq!(back.new_body, "serde body");
    }

    // ── DeleteRequest validation ─────────────────────────────────────

    #[test]
    fn valid_delete_post() {
        let req = DeleteRequest {
            thing_id: "t3_abc123".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn valid_delete_comment() {
        let req = DeleteRequest {
            thing_id: "t1_xyz".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn delete_invalid_thing_id() {
        let req = DeleteRequest {
            thing_id: "bad_id".into(),
        };
        match req.validate().unwrap_err() {
            PostingValidationError::InvalidThingId { id } => {
                assert_eq!(id, "bad_id");
            }
            other => panic!("expected InvalidThingId, got {other:?}"),
        }
    }

    #[test]
    fn delete_empty_thing_id() {
        let req = DeleteRequest {
            thing_id: String::new(),
        };
        assert!(matches!(
            req.validate().unwrap_err(),
            PostingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn delete_t2_thing_id() {
        let req = DeleteRequest {
            thing_id: "t2_user".into(),
        };
        assert!(matches!(
            req.validate().unwrap_err(),
            PostingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn delete_prefix_only_thing_id() {
        let req = DeleteRequest {
            thing_id: "t3_".into(),
        };
        assert!(matches!(
            req.validate().unwrap_err(),
            PostingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn delete_request_debug() {
        let req = DeleteRequest {
            thing_id: "t3_dbg".into(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn delete_request_clone() {
        let req = DeleteRequest {
            thing_id: "t1_cl".into(),
        };
        #[allow(clippy::redundant_clone)]
        let req2 = req.clone();
        assert_eq!(req2.thing_id, "t1_cl");
    }

    #[test]
    fn delete_request_serialize_roundtrip() {
        let req = DeleteRequest {
            thing_id: "t3_ser".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DeleteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thing_id, "t3_ser");
    }

    // ── SubmitResult ─────────────────────────────────────────────────

    #[test]
    fn submit_result_fields() {
        let r = SubmitResult {
            id: "abc123".into(),
            fullname: "t3_abc123".into(),
            url: "https://reddit.com/r/rust/comments/abc123".into(),
            success: true,
        };
        assert_eq!(r.id, "abc123");
        assert_eq!(r.fullname, "t3_abc123");
        assert!(r.success);
    }

    #[test]
    fn submit_result_failed() {
        let r = SubmitResult {
            id: String::new(),
            fullname: String::new(),
            url: String::new(),
            success: false,
        };
        assert!(!r.success);
    }

    #[test]
    fn submit_result_debug() {
        let r = SubmitResult {
            id: "dbg".into(),
            fullname: "t3_dbg".into(),
            url: "https://example.com".into(),
            success: true,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn submit_result_clone() {
        let r = SubmitResult {
            id: "cl".into(),
            fullname: "t3_cl".into(),
            url: "https://example.com".into(),
            success: true,
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.id, "cl");
    }

    #[test]
    fn submit_result_serialize_roundtrip() {
        let r = SubmitResult {
            id: "ser".into(),
            fullname: "t3_ser".into(),
            url: "https://reddit.com/r/test".into(),
            success: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SubmitResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "ser");
        assert!(back.success);
    }

    // ── PostingDecision ──────────────────────────────────────────────

    #[test]
    fn decision_allow() {
        let d = PostingDecision::Allow;
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert!(!d.is_approval_required());
    }

    #[test]
    fn decision_deny() {
        let d = PostingDecision::Deny {
            reason: "nope".into(),
        };
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert!(!d.is_approval_required());
    }

    #[test]
    fn decision_require_approval() {
        let d = PostingDecision::RequireApproval {
            reason: "needs review".into(),
        };
        assert!(!d.is_allowed());
        assert!(!d.is_denied());
        assert!(d.is_approval_required());
    }

    #[test]
    fn decision_eq() {
        assert_eq!(PostingDecision::Allow, PostingDecision::Allow);
        assert_ne!(
            PostingDecision::Allow,
            PostingDecision::Deny {
                reason: "x".into()
            }
        );
    }

    #[test]
    fn decision_debug() {
        let dbg = format!("{:?}", PostingDecision::Allow);
        assert!(dbg.contains("Allow"));
    }

    #[test]
    fn decision_clone() {
        let d = PostingDecision::Deny {
            reason: "test".into(),
        };
        #[allow(clippy::redundant_clone)]
        let d2 = d.clone();
        assert!(d2.is_denied());
    }

    #[test]
    fn decision_serialize_roundtrip() {
        let d = PostingDecision::RequireApproval {
            reason: "review".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: PostingDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    // ── PostingPolicy ────────────────────────────────────────────────

    #[test]
    fn permissive_policy_allows_all() {
        let p = PostingPolicy::new_permissive();
        assert!(p.check_post("rust").is_allowed());
        assert!(p.check_comment().is_allowed());
        assert!(p.check_edit().is_allowed());
        assert!(p.check_delete().is_allowed());
    }

    #[test]
    fn readonly_policy_denies_all() {
        let p = PostingPolicy::new_readonly();
        assert!(p.check_post("rust").is_denied());
        assert!(p.check_comment().is_denied());
        assert!(p.check_edit().is_denied());
        assert!(p.check_delete().is_denied());
    }

    #[test]
    fn policy_post_disabled() {
        let mut p = PostingPolicy::new_permissive();
        p.allow_post = false;
        assert!(p.check_post("rust").is_denied());
    }

    #[test]
    fn policy_comment_disabled() {
        let mut p = PostingPolicy::new_permissive();
        p.allow_comment = false;
        assert!(p.check_comment().is_denied());
    }

    #[test]
    fn policy_edit_disabled() {
        let mut p = PostingPolicy::new_permissive();
        p.allow_edit = false;
        assert!(p.check_edit().is_denied());
    }

    #[test]
    fn policy_delete_disabled() {
        let mut p = PostingPolicy::new_permissive();
        p.allow_delete = false;
        assert!(p.check_delete().is_denied());
    }

    #[test]
    fn policy_post_requires_approval() {
        let mut p = PostingPolicy::new_permissive();
        p.require_approval_for_post = true;
        assert!(p.check_post("rust").is_approval_required());
    }

    #[test]
    fn policy_delete_requires_approval() {
        let mut p = PostingPolicy::new_permissive();
        p.require_approval_for_delete = true;
        assert!(p.check_delete().is_approval_required());
    }

    #[test]
    fn policy_blocked_subreddit() {
        let mut p = PostingPolicy::new_permissive();
        p.blocked_subreddits.insert("nsfw_sub".into());
        assert!(p.check_post("nsfw_sub").is_denied());
    }

    #[test]
    fn policy_blocked_subreddit_case_insensitive() {
        let mut p = PostingPolicy::new_permissive();
        p.blocked_subreddits.insert("badplace".into());
        assert!(p.check_post("BadPlace").is_denied());
    }

    #[test]
    fn policy_unblocked_subreddit_allowed() {
        let mut p = PostingPolicy::new_permissive();
        p.blocked_subreddits.insert("banned".into());
        assert!(p.check_post("allowed_sub").is_allowed());
    }

    #[test]
    fn policy_blocked_subreddit_reason() {
        let mut p = PostingPolicy::new_permissive();
        p.blocked_subreddits.insert("bad".into());
        match p.check_post("bad") {
            PostingDecision::Deny { reason } => {
                assert!(reason.contains("bad"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_post_disabled_reason() {
        let p = PostingPolicy::new_readonly();
        match p.check_post("rust") {
            PostingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_comment_disabled_reason() {
        let p = PostingPolicy::new_readonly();
        match p.check_comment() {
            PostingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_edit_disabled_reason() {
        let p = PostingPolicy::new_readonly();
        match p.check_edit() {
            PostingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_delete_disabled_reason() {
        let p = PostingPolicy::new_readonly();
        match p.check_delete() {
            PostingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_permissive_defaults() {
        let p = PostingPolicy::new_permissive();
        assert_eq!(p.max_post_length, 40_000);
        assert_eq!(p.max_comment_length, 10_000);
        assert!(p.blocked_subreddits.is_empty());
        assert_eq!(p.rate_limit_seconds, 0);
    }

    #[test]
    fn policy_readonly_defaults() {
        let p = PostingPolicy::new_readonly();
        assert_eq!(p.max_post_length, 40_000);
        assert_eq!(p.max_comment_length, 10_000);
        assert!(!p.allow_post);
        assert!(!p.allow_comment);
    }

    #[test]
    fn policy_debug() {
        let p = PostingPolicy::new_permissive();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("allow_post"));
    }

    #[test]
    fn policy_clone() {
        let mut p = PostingPolicy::new_permissive();
        p.blocked_subreddits.insert("test".into());
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert!(p2.blocked_subreddits.contains("test"));
    }

    #[test]
    fn policy_serialize_roundtrip() {
        let mut p = PostingPolicy::new_permissive();
        p.rate_limit_seconds = 30;
        p.blocked_subreddits.insert("spam".into());
        let json = serde_json::to_string(&p).unwrap();
        let back: PostingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rate_limit_seconds, 30);
        assert!(back.blocked_subreddits.contains("spam"));
    }

    #[test]
    fn policy_multiple_blocked() {
        let mut p = PostingPolicy::new_permissive();
        p.blocked_subreddits.insert("bad1".into());
        p.blocked_subreddits.insert("bad2".into());
        p.blocked_subreddits.insert("bad3".into());
        assert!(p.check_post("bad1").is_denied());
        assert!(p.check_post("bad2").is_denied());
        assert!(p.check_post("bad3").is_denied());
        assert!(p.check_post("good").is_allowed());
    }

    #[test]
    fn policy_approval_takes_precedence_over_allow() {
        let mut p = PostingPolicy::new_permissive();
        p.require_approval_for_post = true;
        // Should be approval, not allow
        assert!(p.check_post("rust").is_approval_required());
    }

    #[test]
    fn policy_blocked_takes_precedence_over_approval() {
        let mut p = PostingPolicy::new_permissive();
        p.require_approval_for_post = true;
        p.blocked_subreddits.insert("blocked".into());
        // Should be deny (blocked), not approval
        assert!(p.check_post("blocked").is_denied());
    }

    #[test]
    fn policy_disabled_takes_precedence_over_blocked() {
        let mut p = PostingPolicy::new_readonly();
        p.blocked_subreddits.insert("blocked".into());
        // Should be deny (disabled), message should mention disabled
        match p.check_post("blocked") {
            PostingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // ── PostingValidator ─────────────────────────────────────────────

    #[test]
    fn validator_default() {
        let v = PostingValidator::default();
        assert_eq!(v.max_title_length, 300);
        assert_eq!(v.max_body_length, 40_000);
        assert_eq!(v.max_comment_length, 10_000);
    }

    #[test]
    fn validator_debug() {
        let v = PostingValidator::default();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("max_title_length"));
    }

    #[test]
    fn validator_clone() {
        let v = PostingValidator {
            max_title_length: 100,
            ..Default::default()
        };
        #[allow(clippy::redundant_clone)]
        let v2 = v.clone();
        assert_eq!(v2.max_title_length, 100);
    }

    #[test]
    fn validator_serialize_roundtrip() {
        let v = PostingValidator {
            max_title_length: 200,
            max_body_length: 5000,
            max_comment_length: 1000,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PostingValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_title_length, 200);
        assert_eq!(back.max_body_length, 5000);
        assert_eq!(back.max_comment_length, 1000);
    }

    // ── PostingValidationError ───────────────────────────────────────

    #[test]
    fn validation_error_display_empty_title() {
        assert_eq!(
            PostingValidationError::EmptyTitle.to_string(),
            "Post title must not be empty"
        );
    }

    #[test]
    fn validation_error_display_title_too_long() {
        let e = PostingValidationError::TitleTooLong {
            length: 350,
            max: 300,
        };
        let s = e.to_string();
        assert!(s.contains("350"));
        assert!(s.contains("300"));
    }

    #[test]
    fn validation_error_display_empty_body() {
        assert_eq!(
            PostingValidationError::EmptyBody.to_string(),
            "Body text must not be empty"
        );
    }

    #[test]
    fn validation_error_display_body_too_long() {
        let e = PostingValidationError::BodyTooLong {
            length: 50_000,
            max: 40_000,
        };
        let s = e.to_string();
        assert!(s.contains("50000"));
        assert!(s.contains("40000"));
    }

    #[test]
    fn validation_error_display_invalid_parent_id() {
        let e = PostingValidationError::InvalidParentId {
            id: "bad".into(),
        };
        let s = e.to_string();
        assert!(s.contains("bad"));
        assert!(s.contains("t1_"));
        assert!(s.contains("t3_"));
    }

    #[test]
    fn validation_error_display_invalid_thing_id() {
        let e = PostingValidationError::InvalidThingId {
            id: "oops".into(),
        };
        let s = e.to_string();
        assert!(s.contains("oops"));
    }

    #[test]
    fn validation_error_display_missing_url() {
        assert_eq!(
            PostingValidationError::MissingUrl.to_string(),
            "URL is required for link posts"
        );
    }

    #[test]
    fn validation_error_display_blocked_subreddit() {
        let e = PostingValidationError::BlockedSubreddit {
            subreddit: "banned".into(),
        };
        let s = e.to_string();
        assert!(s.contains("banned"));
    }

    #[test]
    fn validation_error_is_error() {
        let e = PostingValidationError::EmptyTitle;
        // Verify it implements std::error::Error via dyn dispatch.
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            PostingValidationError::EmptyTitle,
            PostingValidationError::EmptyTitle
        );
        assert_ne!(
            PostingValidationError::EmptyTitle,
            PostingValidationError::EmptyBody
        );
    }

    #[test]
    fn validation_error_debug() {
        let dbg = format!("{:?}", PostingValidationError::MissingUrl);
        assert!(dbg.contains("MissingUrl"));
    }

    #[test]
    fn validation_error_clone() {
        let e = PostingValidationError::TitleTooLong {
            length: 999,
            max: 300,
        };
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2, PostingValidationError::TitleTooLong {
            length: 999,
            max: 300,
        });
    }

    #[test]
    fn validation_error_serialize_roundtrip() {
        let e = PostingValidationError::BlockedSubreddit {
            subreddit: "test".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: PostingValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    // ── PostingAction ────────────────────────────────────────────────

    #[test]
    fn posting_action_display() {
        assert_eq!(PostingAction::Post.to_string(), "post");
        assert_eq!(PostingAction::Comment.to_string(), "comment");
        assert_eq!(PostingAction::Edit.to_string(), "edit");
        assert_eq!(PostingAction::Delete.to_string(), "delete");
    }

    #[test]
    fn posting_action_eq() {
        assert_eq!(PostingAction::Post, PostingAction::Post);
        assert_ne!(PostingAction::Post, PostingAction::Comment);
    }

    #[test]
    fn posting_action_clone() {
        let a = PostingAction::Edit;
        #[allow(clippy::redundant_clone)]
        let a2 = a.clone();
        assert_eq!(a2, PostingAction::Edit);
    }

    #[test]
    fn posting_action_debug() {
        let dbg = format!("{:?}", PostingAction::Delete);
        assert!(dbg.contains("Delete"));
    }

    #[test]
    fn posting_action_serialize_roundtrip() {
        for action in [
            PostingAction::Post,
            PostingAction::Comment,
            PostingAction::Edit,
            PostingAction::Delete,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: PostingAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    // ── PostingAuditEvent ────────────────────────────────────────────

    #[test]
    fn audit_event_new() {
        let e = PostingAuditEvent::new(
            1_700_000_000,
            PostingAction::Post,
            Some("t3_abc".into()),
            Some("rust".into()),
            500,
            true,
        );
        assert_eq!(e.timestamp, 1_700_000_000);
        assert_eq!(e.action, PostingAction::Post);
        assert_eq!(e.thing_id.as_deref(), Some("t3_abc"));
        assert_eq!(e.subreddit.as_deref(), Some("rust"));
        assert_eq!(e.content_length, 500);
        assert!(e.was_allowed);
    }

    #[test]
    fn audit_event_for_post() {
        let e = PostingAuditEvent::for_post(100, "rust", 1234, true);
        assert_eq!(e.action, PostingAction::Post);
        assert_eq!(e.subreddit.as_deref(), Some("rust"));
        assert!(e.thing_id.is_none());
        assert_eq!(e.content_length, 1234);
        assert!(e.was_allowed);
    }

    #[test]
    fn audit_event_for_post_denied() {
        let e = PostingAuditEvent::for_post(100, "bad_sub", 0, false);
        assert!(!e.was_allowed);
    }

    #[test]
    fn audit_event_for_comment() {
        let e = PostingAuditEvent::for_comment(200, "t3_parent", 50, true);
        assert_eq!(e.action, PostingAction::Comment);
        assert_eq!(e.thing_id.as_deref(), Some("t3_parent"));
        assert!(e.subreddit.is_none());
        assert_eq!(e.content_length, 50);
    }

    #[test]
    fn audit_event_for_edit() {
        let e = PostingAuditEvent::for_edit(300, "t1_xyz", 100, true);
        assert_eq!(e.action, PostingAction::Edit);
        assert_eq!(e.thing_id.as_deref(), Some("t1_xyz"));
        assert_eq!(e.content_length, 100);
    }

    #[test]
    fn audit_event_for_delete() {
        let e = PostingAuditEvent::for_delete(400, "t3_del", true);
        assert_eq!(e.action, PostingAction::Delete);
        assert_eq!(e.thing_id.as_deref(), Some("t3_del"));
        assert_eq!(e.content_length, 0);
        assert!(e.was_allowed);
    }

    #[test]
    fn audit_event_for_delete_denied() {
        let e = PostingAuditEvent::for_delete(400, "t3_del", false);
        assert!(!e.was_allowed);
    }

    #[test]
    fn audit_event_debug() {
        let e = PostingAuditEvent::for_post(100, "rust", 50, true);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Post"));
        assert!(dbg.contains("rust"));
    }

    #[test]
    fn audit_event_clone() {
        let e = PostingAuditEvent::for_comment(200, "t3_cl", 10, true);
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.action, PostingAction::Comment);
        assert_eq!(e2.content_length, 10);
    }

    #[test]
    fn audit_event_serialize_roundtrip() {
        let e = PostingAuditEvent::for_edit(300, "t1_ser", 200, true);
        let json = serde_json::to_string(&e).unwrap();
        let back: PostingAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp, 300);
        assert_eq!(back.action, PostingAction::Edit);
        assert_eq!(back.thing_id.as_deref(), Some("t1_ser"));
    }

    // ── Fullname format validation helpers ───────────────────────────

    #[test]
    fn validate_parent_id_t1() {
        assert!(validate_parent_id("t1_abc").is_ok());
    }

    #[test]
    fn validate_parent_id_t3() {
        assert!(validate_parent_id("t3_xyz123").is_ok());
    }

    #[test]
    fn validate_parent_id_t2_rejected() {
        assert!(validate_parent_id("t2_user").is_err());
    }

    #[test]
    fn validate_parent_id_t4_rejected() {
        assert!(validate_parent_id("t4_link").is_err());
    }

    #[test]
    fn validate_parent_id_empty() {
        assert!(validate_parent_id("").is_err());
    }

    #[test]
    fn validate_parent_id_prefix_only_t1() {
        assert!(validate_parent_id("t1_").is_err());
    }

    #[test]
    fn validate_parent_id_prefix_only_t3() {
        assert!(validate_parent_id("t3_").is_err());
    }

    #[test]
    fn validate_parent_id_no_underscore() {
        assert!(validate_parent_id("t3abc").is_err());
    }

    #[test]
    fn validate_thing_id_t1() {
        assert!(validate_thing_id("t1_comment").is_ok());
    }

    #[test]
    fn validate_thing_id_t3() {
        assert!(validate_thing_id("t3_post").is_ok());
    }

    #[test]
    fn validate_thing_id_t2_rejected() {
        assert!(validate_thing_id("t2_user").is_err());
    }

    #[test]
    fn validate_thing_id_t5_rejected() {
        assert!(validate_thing_id("t5_sub").is_err());
    }

    #[test]
    fn validate_thing_id_empty() {
        assert!(validate_thing_id("").is_err());
    }

    #[test]
    fn validate_thing_id_prefix_only() {
        assert!(validate_thing_id("t1_").is_err());
    }

    #[test]
    fn validate_thing_id_random_string() {
        assert!(validate_thing_id("hello_world").is_err());
    }

    #[test]
    fn validate_thing_id_numeric_only() {
        assert!(validate_thing_id("12345").is_err());
    }

    // ── Edge cases / integration ─────────────────────────────────────

    #[test]
    fn post_with_all_fields() {
        let req = SubmitPostRequest {
            subreddit: "rust".into(),
            title: "All fields".into(),
            post_kind: PostKind::Text,
            body: Some("Full body text".into()),
            url: Some("https://example.com".into()),
            nsfw: true,
            spoiler: true,
            flair_id: Some("flair_abc".into()),
            send_replies: false,
        };
        assert!(req.validate(&default_validator()).is_ok());
        assert!(req.nsfw);
        assert!(req.spoiler);
        assert!(!req.send_replies);
        assert_eq!(req.flair_id.as_deref(), Some("flair_abc"));
    }

    #[test]
    fn policy_and_validation_combined() {
        let policy = PostingPolicy::new_permissive();
        let validator = PostingValidator::default();

        let req = text_post("rust", "Combined test", Some("body"));
        let decision = policy.check_post(&req.subreddit);
        assert!(decision.is_allowed());
        assert!(req.validate(&validator).is_ok());
    }

    #[test]
    fn policy_denies_before_validation() {
        let policy = PostingPolicy::new_readonly();
        let req = text_post("rust", "", None);
        let decision = policy.check_post(&req.subreddit);
        assert!(decision.is_denied());
        // Validation would also fail but policy check comes first
    }

    #[test]
    fn audit_event_zero_timestamp() {
        let e = PostingAuditEvent::for_post(0, "test", 0, true);
        assert_eq!(e.timestamp, 0);
    }

    #[test]
    fn audit_event_large_content_length() {
        let e = PostingAuditEvent::for_post(100, "test", usize::MAX, true);
        assert_eq!(e.content_length, usize::MAX);
    }

    #[test]
    fn delete_request_t1_prefix() {
        let req = DeleteRequest {
            thing_id: "t1_abc123".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn edit_body_exactly_max() {
        let v = PostingValidator {
            max_body_length: 100,
            ..Default::default()
        };
        let req = EditRequest {
            thing_id: "t3_abc".into(),
            new_body: "x".repeat(100),
        };
        assert!(req.validate(&v).is_ok());
    }

    #[test]
    fn edit_body_one_over_max() {
        let v = PostingValidator {
            max_body_length: 100,
            ..Default::default()
        };
        let req = EditRequest {
            thing_id: "t3_abc".into(),
            new_body: "x".repeat(101),
        };
        assert!(req.validate(&v).is_err());
    }
}
