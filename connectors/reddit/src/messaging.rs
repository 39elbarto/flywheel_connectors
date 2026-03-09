//! `Reddit` inbox and direct messaging support.
//!
//! This module provides types for fetching the authenticated user's inbox,
//! sending direct messages, and marking messages as read. Privacy-sensitive
//! operations **never** log message content in audit events.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ── Inbox category ─────────────────────────────────────────────────────

/// Category filter for the `Reddit` inbox endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InboxCategory {
    /// All messages (default).
    #[default]
    All,
    /// Only unread messages.
    Unread,
    /// Direct messages.
    Messages,
    /// Replies to the user's comments.
    CommentReplies,
    /// Replies to the user's posts.
    PostReplies,
    /// Username mentions.
    Mentions,
}

impl InboxCategory {
    /// Returns the `Reddit` API path segment for this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "inbox",
            Self::Unread => "unread",
            Self::Messages => "messages",
            Self::CommentReplies => "comment_replies",
            Self::PostReplies => "post_replies",
            Self::Mentions => "mentions",
        }
    }
}

// ── Inbox item kind ────────────────────────────────────────────────────

/// The kind of an inbox item returned by the `Reddit` API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InboxItemKind {
    /// A direct message (t4).
    Message,
    /// A reply to one of the user's comments.
    CommentReply,
    /// A reply to one of the user's posts.
    PostReply,
    /// A username mention.
    Mention,
    /// Moderator mail.
    ModMail,
}

// ── Inbox item ─────────────────────────────────────────────────────────

/// A single item from the `Reddit` inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    /// `Reddit` fullname (e.g. `t4_abc123`).
    pub id: String,
    /// Classification of the inbox item.
    pub kind: InboxItemKind,
    /// Subject line — present for direct messages, absent for comment replies.
    pub subject: Option<String>,
    /// Message body (markdown).
    pub body: String,
    /// Author username (without `u/` prefix).
    pub author: String,
    /// Subreddit context, if the item originated in a subreddit.
    pub subreddit: Option<String>,
    /// Unix timestamp (seconds since epoch, UTC).
    pub created_utc: f64,
    /// Whether this item is unread.
    pub new: bool,
    /// Parent fullname, for threaded messages.
    pub parent_id: Option<String>,
    /// Permalink or context URL fragment.
    pub context: Option<String>,
}

// ── Inbox page ─────────────────────────────────────────────────────────

/// A paginated page of `Reddit` inbox items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxPage {
    /// Items on this page.
    pub items: Vec<InboxItem>,
    /// Cursor for the next page, if any.
    pub after: Option<String>,
    /// Cursor for the previous page, if any.
    pub before: Option<String>,
    /// Total count hint returned by `Reddit`.
    pub count: u32,
    /// Whether more pages are available.
    pub has_more: bool,
}

// ── Inbox query ────────────────────────────────────────────────────────

/// Query parameters for fetching the `Reddit` inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxQuery {
    /// Which category to fetch.
    pub category: InboxCategory,
    /// Maximum items per page (default 25, max 100).
    pub limit: u32,
    /// Pagination cursor — fetch items after this fullname.
    pub after: Option<String>,
    /// Whether the fetched items should be marked as read.
    pub mark_read: bool,
}

impl Default for InboxQuery {
    fn default() -> Self {
        Self {
            category: InboxCategory::default(),
            limit: 25,
            after: None,
            mark_read: false,
        }
    }
}

impl InboxQuery {
    /// Create a new query with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the page limit (clamped to 1..=100).
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = if limit == 0 {
            1
        } else if limit > 100 {
            100
        } else {
            limit
        };
        self
    }

    /// Set the pagination cursor.
    #[must_use]
    pub fn with_after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    /// Request that fetched messages be marked as read.
    #[must_use]
    pub const fn mark_read(mut self) -> Self {
        self.mark_read = true;
        self
    }

    /// Validate the query, returning an error if the limit is out of range.
    ///
    /// # Errors
    ///
    /// Returns `MessagingValidationError::BatchTooLarge` if `limit` exceeds 100.
    pub const fn validate(&self) -> Result<(), MessagingValidationError> {
        if self.limit > 100 {
            return Err(MessagingValidationError::BatchTooLarge {
                max: 100,
                got: self.limit as usize,
            });
        }
        Ok(())
    }
}

// ── Send message request ───────────────────────────────────────────────

/// Request to send a `Reddit` direct message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient username (without `u/` prefix).
    pub to: String,
    /// Message subject (max 100 characters).
    pub subject: String,
    /// Message body in markdown (max 10 000 characters).
    pub body: String,
}

impl SendMessageRequest {
    /// Validate the send request.
    ///
    /// # Errors
    ///
    /// Returns a [`MessagingValidationError`] if any field is invalid.
    pub fn validate(&self) -> Result<(), MessagingValidationError> {
        if self.to.is_empty() {
            return Err(MessagingValidationError::EmptyRecipient);
        }
        if self.subject.is_empty() {
            return Err(MessagingValidationError::EmptySubject);
        }
        if self.subject.len() > 100 {
            return Err(MessagingValidationError::SubjectTooLong {
                max: 100,
                got: self.subject.len(),
            });
        }
        if self.body.is_empty() {
            return Err(MessagingValidationError::EmptyBody);
        }
        if self.body.len() > 10_000 {
            return Err(MessagingValidationError::BodyTooLong {
                max: 10_000,
                got: self.body.len(),
            });
        }
        Ok(())
    }
}

// ── Message result ─────────────────────────────────────────────────────

/// Result of sending a `Reddit` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResult {
    /// Whether the send succeeded.
    pub success: bool,
    /// Error message from the `Reddit` API, if any.
    pub error_message: Option<String>,
}

// ── Mark-read request ──────────────────────────────────────────────────

/// Request to mark one or more `Reddit` inbox items as read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkReadRequest {
    /// Fullnames of the items to mark as read (e.g. `["t4_abc", "t1_xyz"]`).
    pub thing_ids: Vec<String>,
}

impl MarkReadRequest {
    /// Validate the request.
    ///
    /// # Errors
    ///
    /// Returns a [`MessagingValidationError`] if the batch is empty or any
    /// fullname is invalid.
    pub fn validate(&self) -> Result<(), MessagingValidationError> {
        if self.thing_ids.is_empty() {
            return Err(MessagingValidationError::EmptyBatch);
        }
        for id in &self.thing_ids {
            if !is_valid_fullname(id) {
                return Err(MessagingValidationError::InvalidThingId {
                    id: id.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Check whether a string looks like a valid `Reddit` fullname (`tN_xxx`).
fn is_valid_fullname(id: &str) -> bool {
    let Some((prefix, suffix)) = id.split_once('_') else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    matches!(prefix, "t1" | "t2" | "t3" | "t4" | "t5" | "t6")
}

// ── Messaging policy ──────────────────────────────────────────────────

/// Policy governing which messaging operations are allowed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingPolicy {
    /// Allow reading the inbox.
    pub allow_read_inbox: bool,
    /// Allow sending direct messages.
    pub allow_send: bool,
    /// Allow marking messages as read.
    pub allow_mark_read: bool,
    /// Require human approval before sending.
    pub require_approval_for_send: bool,
    /// Usernames that must never receive messages.
    pub blocked_recipients: HashSet<String>,
    /// Maximum message body length (default 10 000).
    pub max_message_length: usize,
}

impl Default for MessagingPolicy {
    fn default() -> Self {
        Self {
            allow_read_inbox: true,
            allow_send: true,
            allow_mark_read: true,
            require_approval_for_send: false,
            blocked_recipients: HashSet::new(),
            max_message_length: 10_000,
        }
    }
}

impl MessagingPolicy {
    /// A fully permissive policy (read, send, mark-read all allowed).
    #[must_use]
    pub fn new_permissive() -> Self {
        Self::default()
    }

    /// A read-only policy that disables sending and mark-read.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_read_inbox: true,
            allow_send: false,
            allow_mark_read: false,
            require_approval_for_send: false,
            blocked_recipients: HashSet::new(),
            max_message_length: 10_000,
        }
    }

    /// Evaluate whether a send operation should be allowed.
    #[must_use]
    pub fn check_send(&self, recipient: &str) -> MessagingDecision {
        if !self.allow_send {
            return MessagingDecision::Deny {
                reason: "sending messages is disabled by policy".into(),
            };
        }
        if self.blocked_recipients.contains(recipient) {
            return MessagingDecision::Deny {
                reason: format!("recipient '{recipient}' is blocked by policy"),
            };
        }
        if self.require_approval_for_send {
            return MessagingDecision::RequireApproval {
                reason: "policy requires human approval before sending".into(),
            };
        }
        MessagingDecision::Allow
    }

    /// Evaluate whether a mark-read operation should be allowed.
    #[must_use]
    pub fn check_mark_read(&self) -> MessagingDecision {
        if !self.allow_mark_read {
            return MessagingDecision::Deny {
                reason: "marking messages as read is disabled by policy".into(),
            };
        }
        MessagingDecision::Allow
    }
}

// ── Messaging decision ────────────────────────────────────────────────

/// Decision from a [`MessagingPolicy`] check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessagingDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// The operation requires human approval before proceeding.
    RequireApproval {
        /// Human-readable reason for requiring approval.
        reason: String,
    },
}

// ── Messaging validator ───────────────────────────────────────────────

/// Validates messaging requests against configurable limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingValidator {
    /// Maximum subject length for outgoing messages.
    pub max_subject_length: usize,
    /// Maximum body length for outgoing messages.
    pub max_body_length: usize,
    /// Maximum number of thing IDs in a single mark-read batch.
    pub max_mark_read_batch: usize,
}

impl Default for MessagingValidator {
    fn default() -> Self {
        Self {
            max_subject_length: 100,
            max_body_length: 10_000,
            max_mark_read_batch: 25,
        }
    }
}

impl MessagingValidator {
    /// Validate a send-message request.
    ///
    /// # Errors
    ///
    /// Returns a [`MessagingValidationError`] if any field is invalid.
    pub fn validate_send(&self, req: &SendMessageRequest) -> Result<(), MessagingValidationError> {
        if req.to.is_empty() {
            return Err(MessagingValidationError::EmptyRecipient);
        }
        if req.subject.is_empty() {
            return Err(MessagingValidationError::EmptySubject);
        }
        if req.subject.len() > self.max_subject_length {
            return Err(MessagingValidationError::SubjectTooLong {
                max: self.max_subject_length,
                got: req.subject.len(),
            });
        }
        if req.body.is_empty() {
            return Err(MessagingValidationError::EmptyBody);
        }
        if req.body.len() > self.max_body_length {
            return Err(MessagingValidationError::BodyTooLong {
                max: self.max_body_length,
                got: req.body.len(),
            });
        }
        Ok(())
    }

    /// Validate a mark-read request.
    ///
    /// # Errors
    ///
    /// Returns a [`MessagingValidationError`] if the batch is empty, too large,
    /// or contains invalid fullnames.
    pub fn validate_mark_read(
        &self,
        req: &MarkReadRequest,
    ) -> Result<(), MessagingValidationError> {
        if req.thing_ids.is_empty() {
            return Err(MessagingValidationError::EmptyBatch);
        }
        if req.thing_ids.len() > self.max_mark_read_batch {
            return Err(MessagingValidationError::BatchTooLarge {
                max: self.max_mark_read_batch as u32,
                got: req.thing_ids.len(),
            });
        }
        for id in &req.thing_ids {
            if !is_valid_fullname(id) {
                return Err(MessagingValidationError::InvalidThingId {
                    id: id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Validate an inbox query.
    ///
    /// # Errors
    ///
    /// Returns a [`MessagingValidationError`] if the limit is out of range.
    pub const fn validate_query(&self, query: &InboxQuery) -> Result<(), MessagingValidationError> {
        if query.limit > 100 {
            return Err(MessagingValidationError::BatchTooLarge {
                max: 100,
                got: query.limit as usize,
            });
        }
        Ok(())
    }
}

// ── Validation error ──────────────────────────────────────────────────

/// Errors arising from messaging request validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessagingValidationError {
    /// The recipient field is empty.
    EmptyRecipient,
    /// The subject field is empty.
    EmptySubject,
    /// The subject exceeds the maximum length.
    SubjectTooLong {
        /// Maximum allowed length.
        max: usize,
        /// Actual length.
        got: usize,
    },
    /// The body field is empty.
    EmptyBody,
    /// The body exceeds the maximum length.
    BodyTooLong {
        /// Maximum allowed length.
        max: usize,
        /// Actual length.
        got: usize,
    },
    /// The recipient is on the blocked list.
    BlockedRecipient {
        /// The blocked username.
        username: String,
    },
    /// The batch of thing IDs is empty.
    EmptyBatch,
    /// The batch exceeds the maximum size.
    BatchTooLarge {
        /// Maximum allowed batch size.
        max: u32,
        /// Actual batch size.
        got: usize,
    },
    /// A thing ID is not a valid `Reddit` fullname.
    InvalidThingId {
        /// The invalid ID.
        id: String,
    },
}

impl std::fmt::Display for MessagingValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRecipient => write!(f, "recipient must not be empty"),
            Self::EmptySubject => write!(f, "subject must not be empty"),
            Self::SubjectTooLong { max, got } => {
                write!(f, "subject too long ({got} > {max} chars)")
            }
            Self::EmptyBody => write!(f, "body must not be empty"),
            Self::BodyTooLong { max, got } => {
                write!(f, "body too long ({got} > {max} chars)")
            }
            Self::BlockedRecipient { username } => {
                write!(f, "recipient '{username}' is blocked")
            }
            Self::EmptyBatch => write!(f, "thing_ids must not be empty"),
            Self::BatchTooLarge { max, got } => {
                write!(f, "batch too large ({got} > {max})")
            }
            Self::InvalidThingId { id } => {
                write!(f, "invalid Reddit fullname: '{id}'")
            }
        }
    }
}

impl std::error::Error for MessagingValidationError {}

// ── Audit event ────────────────────────────────────────────────────────

/// Action recorded by [`MessagingAuditEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessagingAuditAction {
    /// Inbox was read.
    Read,
    /// A message was sent.
    Send,
    /// Messages were marked as read.
    MarkRead,
}

/// Privacy-safe audit event for messaging operations.
///
/// **Important:** This struct intentionally omits message body and subject
/// content. Only metadata (action, recipient, count, allowed) is recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingAuditEvent {
    /// When the event occurred (seconds since epoch, UTC).
    pub timestamp: f64,
    /// Which action was performed.
    pub action: MessagingAuditAction,
    /// Recipient username — populated only for [`MessagingAuditAction::Send`].
    pub recipient: Option<String>,
    /// Number of messages involved (items fetched, IDs marked, etc.).
    pub message_count: u32,
    /// Whether the policy allowed the operation.
    pub was_allowed: bool,
}

impl MessagingAuditEvent {
    /// Create an audit event for an inbox read.
    #[must_use]
    pub const fn inbox_read(timestamp: f64, count: u32, allowed: bool) -> Self {
        Self {
            timestamp,
            action: MessagingAuditAction::Read,
            recipient: None,
            message_count: count,
            was_allowed: allowed,
        }
    }

    /// Create an audit event for sending a message. The body/subject are
    /// deliberately **not** recorded.
    #[must_use]
    pub fn message_sent(timestamp: f64, recipient: &str, allowed: bool) -> Self {
        Self {
            timestamp,
            action: MessagingAuditAction::Send,
            recipient: Some(recipient.to_owned()),
            message_count: 1,
            was_allowed: allowed,
        }
    }

    /// Create an audit event for marking messages as read.
    #[must_use]
    pub const fn mark_read(timestamp: f64, count: u32, allowed: bool) -> Self {
        Self {
            timestamp,
            action: MessagingAuditAction::MarkRead,
            recipient: None,
            message_count: count,
            was_allowed: allowed,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── InboxCategory ──────────────────────────────────────────────────

    #[test]
    fn inbox_category_as_str_all() {
        assert_eq!(InboxCategory::All.as_str(), "inbox");
    }

    #[test]
    fn inbox_category_as_str_unread() {
        assert_eq!(InboxCategory::Unread.as_str(), "unread");
    }

    #[test]
    fn inbox_category_as_str_messages() {
        assert_eq!(InboxCategory::Messages.as_str(), "messages");
    }

    #[test]
    fn inbox_category_as_str_comment_replies() {
        assert_eq!(InboxCategory::CommentReplies.as_str(), "comment_replies");
    }

    #[test]
    fn inbox_category_as_str_post_replies() {
        assert_eq!(InboxCategory::PostReplies.as_str(), "post_replies");
    }

    #[test]
    fn inbox_category_as_str_mentions() {
        assert_eq!(InboxCategory::Mentions.as_str(), "mentions");
    }

    #[test]
    fn inbox_category_default_is_all() {
        assert_eq!(InboxCategory::default(), InboxCategory::All);
    }

    #[test]
    fn inbox_category_eq() {
        assert_eq!(InboxCategory::Unread, InboxCategory::Unread);
        assert_ne!(InboxCategory::All, InboxCategory::Unread);
    }

    #[test]
    fn inbox_category_clone() {
        let cat = InboxCategory::Mentions;
        let cat2 = cat;
        assert_eq!(cat, cat2);
    }

    #[test]
    fn inbox_category_debug() {
        let dbg = format!("{:?}", InboxCategory::CommentReplies);
        assert!(dbg.contains("CommentReplies"));
    }

    #[test]
    fn inbox_category_serialize_roundtrip() {
        let json = serde_json::to_string(&InboxCategory::PostReplies).unwrap();
        let back: InboxCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, InboxCategory::PostReplies);
    }

    #[test]
    fn inbox_category_hash() {
        let mut set = HashSet::new();
        set.insert(InboxCategory::All);
        set.insert(InboxCategory::All);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn inbox_category_copy() {
        let cat = InboxCategory::Mentions;
        let cat2 = cat;
        assert_eq!(cat, cat2);
    }

    // ── InboxItemKind ──────────────────────────────────────────────────

    #[test]
    fn inbox_item_kind_eq() {
        assert_eq!(InboxItemKind::Message, InboxItemKind::Message);
        assert_ne!(InboxItemKind::Message, InboxItemKind::CommentReply);
    }

    #[test]
    fn inbox_item_kind_clone() {
        let k = InboxItemKind::ModMail;
        let k2 = k;
        assert_eq!(k, k2);
    }

    #[test]
    fn inbox_item_kind_debug() {
        let dbg = format!("{:?}", InboxItemKind::PostReply);
        assert!(dbg.contains("PostReply"));
    }

    #[test]
    fn inbox_item_kind_serialize_roundtrip() {
        for kind in [
            InboxItemKind::Message,
            InboxItemKind::CommentReply,
            InboxItemKind::PostReply,
            InboxItemKind::Mention,
            InboxItemKind::ModMail,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: InboxItemKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn inbox_item_kind_hash() {
        let mut set = HashSet::new();
        set.insert(InboxItemKind::CommentReply);
        set.insert(InboxItemKind::CommentReply);
        set.insert(InboxItemKind::Mention);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn inbox_item_kind_copy() {
        let k = InboxItemKind::Mention;
        let k2 = k;
        assert_eq!(k, k2);
    }

    // ── InboxItem ──────────────────────────────────────────────────────

    fn sample_inbox_item() -> InboxItem {
        InboxItem {
            id: "t4_abc123".into(),
            kind: InboxItemKind::Message,
            subject: Some("Hello".into()),
            body: "Hi there".into(),
            author: "testuser".into(),
            subreddit: None,
            created_utc: 1_700_000_000.0,
            new: true,
            parent_id: None,
            context: None,
        }
    }

    #[test]
    fn inbox_item_construction() {
        let item = sample_inbox_item();
        assert_eq!(item.id, "t4_abc123");
        assert_eq!(item.kind, InboxItemKind::Message);
        assert!(item.new);
    }

    #[test]
    fn inbox_item_clone() {
        let item = sample_inbox_item();
        let cloned = item.clone();
        assert_eq!(item.id, cloned.id);
        assert_eq!(cloned.body, "Hi there");
    }

    #[test]
    fn inbox_item_debug() {
        let item = sample_inbox_item();
        let dbg = format!("{item:?}");
        assert!(dbg.contains("t4_abc123"));
    }

    #[test]
    fn inbox_item_serialize_roundtrip() {
        let item = sample_inbox_item();
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["id"], "t4_abc123");
        assert_eq!(json["new"], true);
        let back: InboxItem = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "t4_abc123");
    }

    #[test]
    fn inbox_item_with_subreddit_and_context() {
        let item = InboxItem {
            id: "t1_reply".into(),
            kind: InboxItemKind::CommentReply,
            subject: None,
            body: "Good point".into(),
            author: "replyer".into(),
            subreddit: Some("rust".into()),
            created_utc: 1_700_000_100.0,
            new: false,
            parent_id: Some("t1_parent".into()),
            context: Some("/r/rust/comments/abc/test/def".into()),
        };
        assert_eq!(item.subreddit.as_deref(), Some("rust"));
        assert!(item.context.as_ref().unwrap().contains("/r/rust"));
        assert!(!item.new);
    }

    #[test]
    fn inbox_item_mention() {
        let item = InboxItem {
            id: "t1_mention".into(),
            kind: InboxItemKind::Mention,
            subject: Some("username mention".into()),
            body: "Hey u/bot!".into(),
            author: "someone".into(),
            subreddit: Some("test".into()),
            created_utc: 1_700_000_200.0,
            new: true,
            parent_id: Some("t3_post".into()),
            context: Some("/r/test/comments/xyz".into()),
        };
        assert_eq!(item.kind, InboxItemKind::Mention);
        assert!(item.new);
    }

    #[test]
    fn inbox_item_post_reply() {
        let item = InboxItem {
            id: "t1_pr".into(),
            kind: InboxItemKind::PostReply,
            subject: Some("post reply".into()),
            body: "Nice post!".into(),
            author: "fan".into(),
            subreddit: Some("programming".into()),
            created_utc: 1_700_000_300.0,
            new: true,
            parent_id: Some("t3_mypost".into()),
            context: None,
        };
        assert_eq!(item.kind, InboxItemKind::PostReply);
    }

    // ── InboxPage ──────────────────────────────────────────────────────

    #[test]
    fn inbox_page_empty() {
        let page = InboxPage {
            items: vec![],
            after: None,
            before: None,
            count: 0,
            has_more: false,
        };
        assert!(page.items.is_empty());
        assert!(!page.has_more);
    }

    #[test]
    fn inbox_page_with_items() {
        let page = InboxPage {
            items: vec![sample_inbox_item()],
            after: Some("t4_next".into()),
            before: Some("t4_prev".into()),
            count: 1,
            has_more: true,
        };
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.after.as_deref(), Some("t4_next"));
        assert_eq!(page.before.as_deref(), Some("t4_prev"));
        assert!(page.has_more);
    }

    #[test]
    fn inbox_page_clone() {
        let page = InboxPage {
            items: vec![sample_inbox_item()],
            after: None,
            before: None,
            count: 1,
            has_more: false,
        };
        let cloned = page.clone();
        assert_eq!(page.items.len(), cloned.items.len());
        assert_eq!(cloned.count, 1);
    }

    #[test]
    fn inbox_page_debug() {
        let page = InboxPage {
            items: vec![],
            after: Some("cursor".into()),
            before: None,
            count: 0,
            has_more: false,
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("cursor"));
    }

    #[test]
    fn inbox_page_serialize_roundtrip() {
        let page = InboxPage {
            items: vec![sample_inbox_item()],
            after: Some("abc".into()),
            before: None,
            count: 1,
            has_more: true,
        };
        let json = serde_json::to_value(&page).unwrap();
        let back: InboxPage = serde_json::from_value(json).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.after.as_deref(), Some("abc"));
        assert!(back.has_more);
    }

    #[test]
    fn inbox_page_many_items() {
        let items: Vec<InboxItem> = (0..50)
            .map(|i| InboxItem {
                id: format!("t4_{i}"),
                kind: InboxItemKind::Message,
                subject: Some(format!("Msg {i}")),
                body: format!("Body {i}"),
                author: format!("user{i}"),
                subreddit: None,
                created_utc: 1_700_000_000.0 + f64::from(i),
                new: i % 2 == 0,
                parent_id: None,
                context: None,
            })
            .collect();
        let page = InboxPage {
            items,
            after: Some("t4_49".into()),
            before: None,
            count: 50,
            has_more: true,
        };
        assert_eq!(page.items.len(), 50);
        assert_eq!(page.count, 50);
    }

    // ── InboxQuery ─────────────────────────────────────────────────────

    #[test]
    fn inbox_query_default() {
        let q = InboxQuery::new();
        assert_eq!(q.category, InboxCategory::All);
        assert_eq!(q.limit, 25);
        assert!(q.after.is_none());
        assert!(!q.mark_read);
    }

    #[test]
    fn inbox_query_with_limit() {
        let q = InboxQuery::new().with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn inbox_query_limit_clamp_zero() {
        let q = InboxQuery::new().with_limit(0);
        assert_eq!(q.limit, 1);
    }

    #[test]
    fn inbox_query_limit_clamp_over_100() {
        let q = InboxQuery::new().with_limit(200);
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn inbox_query_limit_exact_100() {
        let q = InboxQuery::new().with_limit(100);
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn inbox_query_limit_exact_1() {
        let q = InboxQuery::new().with_limit(1);
        assert_eq!(q.limit, 1);
    }

    #[test]
    fn inbox_query_with_after() {
        let q = InboxQuery::new().with_after("t4_cursor");
        assert_eq!(q.after.as_deref(), Some("t4_cursor"));
    }

    #[test]
    fn inbox_query_mark_read() {
        let q = InboxQuery::new().mark_read();
        assert!(q.mark_read);
    }

    #[test]
    fn inbox_query_builder_chain() {
        let q = InboxQuery::new()
            .with_limit(10)
            .with_after("t4_abc")
            .mark_read();
        assert_eq!(q.limit, 10);
        assert_eq!(q.after.as_deref(), Some("t4_abc"));
        assert!(q.mark_read);
    }

    #[test]
    fn inbox_query_validate_ok() {
        let q = InboxQuery::new();
        assert!(q.validate().is_ok());
    }

    #[test]
    fn inbox_query_validate_limit_100_ok() {
        let q = InboxQuery::new().with_limit(100);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn inbox_query_clone() {
        let q = InboxQuery::new().with_limit(42).with_after("cursor");
        let cloned = q.clone();
        assert_eq!(q.limit, cloned.limit);
        assert_eq!(cloned.after.as_deref(), Some("cursor"));
    }

    #[test]
    fn inbox_query_debug() {
        let q = InboxQuery::new().with_limit(10);
        let dbg = format!("{q:?}");
        assert!(dbg.contains("10"));
    }

    #[test]
    fn inbox_query_serialize_roundtrip() {
        let q = InboxQuery::new().with_limit(30).with_after("pg2").mark_read();
        let json = serde_json::to_value(&q).unwrap();
        let back: InboxQuery = serde_json::from_value(json).unwrap();
        assert_eq!(back.limit, 30);
        assert_eq!(back.after.as_deref(), Some("pg2"));
        assert!(back.mark_read);
    }

    // ── SendMessageRequest ─────────────────────────────────────────────

    fn sample_send_request() -> SendMessageRequest {
        SendMessageRequest {
            to: "recipient".into(),
            subject: "Hello".into(),
            body: "Message body".into(),
        }
    }

    #[test]
    fn send_request_validate_ok() {
        assert!(sample_send_request().validate().is_ok());
    }

    #[test]
    fn send_request_validate_empty_to() {
        let mut req = sample_send_request();
        req.to = String::new();
        assert_eq!(req.validate().unwrap_err(), MessagingValidationError::EmptyRecipient);
    }

    #[test]
    fn send_request_validate_empty_subject() {
        let mut req = sample_send_request();
        req.subject = String::new();
        assert_eq!(req.validate().unwrap_err(), MessagingValidationError::EmptySubject);
    }

    #[test]
    fn send_request_validate_subject_too_long() {
        let mut req = sample_send_request();
        req.subject = "x".repeat(101);
        match req.validate().unwrap_err() {
            MessagingValidationError::SubjectTooLong { max, got } => {
                assert_eq!(max, 100);
                assert_eq!(got, 101);
            }
            other => panic!("expected SubjectTooLong, got {other:?}"),
        }
    }

    #[test]
    fn send_request_validate_subject_exactly_100() {
        let mut req = sample_send_request();
        req.subject = "a".repeat(100);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn send_request_validate_empty_body() {
        let mut req = sample_send_request();
        req.body = String::new();
        assert_eq!(req.validate().unwrap_err(), MessagingValidationError::EmptyBody);
    }

    #[test]
    fn send_request_validate_body_too_long() {
        let mut req = sample_send_request();
        req.body = "y".repeat(10_001);
        match req.validate().unwrap_err() {
            MessagingValidationError::BodyTooLong { max, got } => {
                assert_eq!(max, 10_000);
                assert_eq!(got, 10_001);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    #[test]
    fn send_request_validate_body_exactly_10000() {
        let mut req = sample_send_request();
        req.body = "z".repeat(10_000);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn send_request_clone() {
        let req = sample_send_request();
        let cloned = req.clone();
        assert_eq!(req.to, cloned.to);
        assert_eq!(cloned.subject, "Hello");
    }

    #[test]
    fn send_request_debug() {
        let dbg = format!("{:?}", sample_send_request());
        assert!(dbg.contains("recipient"));
    }

    #[test]
    fn send_request_serialize_roundtrip() {
        let req = sample_send_request();
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["to"], "recipient");
        let back: SendMessageRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.to, "recipient");
    }

    // ── MessageResult ──────────────────────────────────────────────────

    #[test]
    fn message_result_success() {
        let r = MessageResult {
            success: true,
            error_message: None,
        };
        assert!(r.success);
        assert!(r.error_message.is_none());
    }

    #[test]
    fn message_result_failure() {
        let r = MessageResult {
            success: false,
            error_message: Some("rate limited".into()),
        };
        assert!(!r.success);
        assert_eq!(r.error_message.as_deref(), Some("rate limited"));
    }

    #[test]
    fn message_result_clone() {
        let r = MessageResult {
            success: true,
            error_message: None,
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert!(r2.success);
    }

    #[test]
    fn message_result_debug() {
        let r = MessageResult {
            success: false,
            error_message: Some("err".into()),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("err"));
    }

    #[test]
    fn message_result_serialize_roundtrip() {
        let r = MessageResult {
            success: true,
            error_message: None,
        };
        let json = serde_json::to_value(&r).unwrap();
        let back: MessageResult = serde_json::from_value(json).unwrap();
        assert!(back.success);
    }

    // ── MarkReadRequest ────────────────────────────────────────────────

    #[test]
    fn mark_read_validate_ok() {
        let req = MarkReadRequest {
            thing_ids: vec!["t4_abc".into(), "t1_xyz".into()],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn mark_read_validate_empty() {
        let req = MarkReadRequest {
            thing_ids: vec![],
        };
        assert_eq!(req.validate().unwrap_err(), MessagingValidationError::EmptyBatch);
    }

    #[test]
    fn mark_read_validate_invalid_fullname_no_underscore() {
        let req = MarkReadRequest {
            thing_ids: vec!["bad".into()],
        };
        match req.validate().unwrap_err() {
            MessagingValidationError::InvalidThingId { id } => assert_eq!(id, "bad"),
            other => panic!("expected InvalidThingId, got {other:?}"),
        }
    }

    #[test]
    fn mark_read_validate_invalid_fullname_wrong_prefix() {
        let req = MarkReadRequest {
            thing_ids: vec!["t9_abc".into()],
        };
        assert!(matches!(
            req.validate().unwrap_err(),
            MessagingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn mark_read_validate_invalid_fullname_empty_suffix() {
        let req = MarkReadRequest {
            thing_ids: vec!["t4_".into()],
        };
        assert!(matches!(
            req.validate().unwrap_err(),
            MessagingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn mark_read_validate_mixed_valid_invalid() {
        let req = MarkReadRequest {
            thing_ids: vec!["t4_good".into(), "invalid".into()],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn mark_read_clone() {
        let req = MarkReadRequest {
            thing_ids: vec!["t4_a".into()],
        };
        let cloned = req.clone();
        assert_eq!(req.thing_ids, cloned.thing_ids);
    }

    #[test]
    fn mark_read_debug() {
        let req = MarkReadRequest {
            thing_ids: vec!["t4_dbg".into()],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("t4_dbg"));
    }

    #[test]
    fn mark_read_serialize_roundtrip() {
        let req = MarkReadRequest {
            thing_ids: vec!["t4_ser1".into(), "t1_ser2".into()],
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: MarkReadRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.thing_ids.len(), 2);
    }

    // ── is_valid_fullname ──────────────────────────────────────────────

    #[test]
    fn valid_fullname_t1() {
        assert!(is_valid_fullname("t1_abc"));
    }

    #[test]
    fn valid_fullname_t2() {
        assert!(is_valid_fullname("t2_user"));
    }

    #[test]
    fn valid_fullname_t3() {
        assert!(is_valid_fullname("t3_post"));
    }

    #[test]
    fn valid_fullname_t4() {
        assert!(is_valid_fullname("t4_msg"));
    }

    #[test]
    fn valid_fullname_t5() {
        assert!(is_valid_fullname("t5_sub"));
    }

    #[test]
    fn valid_fullname_t6() {
        assert!(is_valid_fullname("t6_award"));
    }

    #[test]
    fn invalid_fullname_no_underscore() {
        assert!(!is_valid_fullname("t1abc"));
    }

    #[test]
    fn invalid_fullname_empty_suffix() {
        assert!(!is_valid_fullname("t4_"));
    }

    #[test]
    fn invalid_fullname_wrong_prefix() {
        assert!(!is_valid_fullname("t7_abc"));
    }

    #[test]
    fn invalid_fullname_t0() {
        assert!(!is_valid_fullname("t0_abc"));
    }

    #[test]
    fn invalid_fullname_empty() {
        assert!(!is_valid_fullname(""));
    }

    #[test]
    fn invalid_fullname_just_underscore() {
        assert!(!is_valid_fullname("_abc"));
    }

    #[test]
    fn invalid_fullname_no_t_prefix() {
        assert!(!is_valid_fullname("x1_abc"));
    }

    // ── MessagingPolicy ────────────────────────────────────────────────

    #[test]
    fn policy_permissive_allows_all() {
        let p = MessagingPolicy::new_permissive();
        assert!(p.allow_read_inbox);
        assert!(p.allow_send);
        assert!(p.allow_mark_read);
        assert!(!p.require_approval_for_send);
        assert!(p.blocked_recipients.is_empty());
        assert_eq!(p.max_message_length, 10_000);
    }

    #[test]
    fn policy_readonly() {
        let p = MessagingPolicy::new_readonly();
        assert!(p.allow_read_inbox);
        assert!(!p.allow_send);
        assert!(!p.allow_mark_read);
    }

    #[test]
    fn policy_check_send_allowed() {
        let p = MessagingPolicy::new_permissive();
        assert_eq!(p.check_send("anyone"), MessagingDecision::Allow);
    }

    #[test]
    fn policy_check_send_denied_by_policy() {
        let p = MessagingPolicy::new_readonly();
        match p.check_send("someone") {
            MessagingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_send_blocked_recipient() {
        let mut p = MessagingPolicy::new_permissive();
        p.blocked_recipients.insert("spammer".into());
        match p.check_send("spammer") {
            MessagingDecision::Deny { reason } => {
                assert!(reason.contains("spammer"));
                assert!(reason.contains("blocked"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_send_not_blocked() {
        let mut p = MessagingPolicy::new_permissive();
        p.blocked_recipients.insert("spammer".into());
        assert_eq!(p.check_send("good_user"), MessagingDecision::Allow);
    }

    #[test]
    fn policy_check_send_require_approval() {
        let mut p = MessagingPolicy::new_permissive();
        p.require_approval_for_send = true;
        match p.check_send("anyone") {
            MessagingDecision::RequireApproval { reason } => {
                assert!(reason.contains("approval"));
            }
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_send_blocked_takes_precedence_over_approval() {
        let mut p = MessagingPolicy::new_permissive();
        p.require_approval_for_send = true;
        p.blocked_recipients.insert("blocked_user".into());
        // Blocked should deny outright, not require approval
        assert!(matches!(
            p.check_send("blocked_user"),
            MessagingDecision::Deny { .. }
        ));
    }

    #[test]
    fn policy_check_mark_read_allowed() {
        let p = MessagingPolicy::new_permissive();
        assert_eq!(p.check_mark_read(), MessagingDecision::Allow);
    }

    #[test]
    fn policy_check_mark_read_denied() {
        let p = MessagingPolicy::new_readonly();
        match p.check_mark_read() {
            MessagingDecision::Deny { reason } => {
                assert!(reason.contains("disabled"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_clone() {
        let mut p = MessagingPolicy::new_permissive();
        p.blocked_recipients.insert("test".into());
        let cloned = p.clone();
        assert!(cloned.blocked_recipients.contains("test"));
    }

    #[test]
    fn policy_debug() {
        let p = MessagingPolicy::new_readonly();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("allow_send"));
    }

    #[test]
    fn policy_serialize_roundtrip() {
        let mut p = MessagingPolicy::new_permissive();
        p.blocked_recipients.insert("blocked1".into());
        let json = serde_json::to_value(&p).unwrap();
        let back: MessagingPolicy = serde_json::from_value(json).unwrap();
        assert!(back.blocked_recipients.contains("blocked1"));
        assert!(back.allow_send);
    }

    #[test]
    fn policy_default_is_permissive() {
        let p = MessagingPolicy::default();
        assert!(p.allow_send);
        assert!(p.allow_read_inbox);
        assert!(p.allow_mark_read);
    }

    #[test]
    fn policy_multiple_blocked_recipients() {
        let mut p = MessagingPolicy::new_permissive();
        p.blocked_recipients.insert("bot1".into());
        p.blocked_recipients.insert("bot2".into());
        p.blocked_recipients.insert("bot3".into());
        assert!(matches!(p.check_send("bot1"), MessagingDecision::Deny { .. }));
        assert!(matches!(p.check_send("bot2"), MessagingDecision::Deny { .. }));
        assert!(matches!(p.check_send("bot3"), MessagingDecision::Deny { .. }));
        assert_eq!(p.check_send("legit"), MessagingDecision::Allow);
    }

    // ── MessagingDecision ──────────────────────────────────────────────

    #[test]
    fn decision_allow_eq() {
        assert_eq!(MessagingDecision::Allow, MessagingDecision::Allow);
    }

    #[test]
    fn decision_deny_eq() {
        let d1 = MessagingDecision::Deny {
            reason: "no".into(),
        };
        let d2 = MessagingDecision::Deny {
            reason: "no".into(),
        };
        assert_eq!(d1, d2);
    }

    #[test]
    fn decision_deny_ne() {
        let d1 = MessagingDecision::Deny {
            reason: "a".into(),
        };
        let d2 = MessagingDecision::Deny {
            reason: "b".into(),
        };
        assert_ne!(d1, d2);
    }

    #[test]
    fn decision_require_approval_eq() {
        let d1 = MessagingDecision::RequireApproval {
            reason: "needs review".into(),
        };
        let d2 = MessagingDecision::RequireApproval {
            reason: "needs review".into(),
        };
        assert_eq!(d1, d2);
    }

    #[test]
    fn decision_clone() {
        let d = MessagingDecision::Deny {
            reason: "test".into(),
        };
        #[allow(clippy::redundant_clone)]
        let d2 = d.clone();
        assert_eq!(d2, MessagingDecision::Deny { reason: "test".into() });
    }

    #[test]
    fn decision_debug() {
        let dbg = format!("{:?}", MessagingDecision::Allow);
        assert!(dbg.contains("Allow"));
    }

    #[test]
    fn decision_serialize_roundtrip() {
        for decision in [
            MessagingDecision::Allow,
            MessagingDecision::Deny { reason: "nope".into() },
            MessagingDecision::RequireApproval { reason: "maybe".into() },
        ] {
            let json = serde_json::to_value(&decision).unwrap();
            let back: MessagingDecision = serde_json::from_value(json).unwrap();
            assert_eq!(back, decision);
        }
    }

    // ── MessagingValidator ─────────────────────────────────────────────

    #[test]
    fn validator_default() {
        let v = MessagingValidator::default();
        assert_eq!(v.max_subject_length, 100);
        assert_eq!(v.max_body_length, 10_000);
        assert_eq!(v.max_mark_read_batch, 25);
    }

    #[test]
    fn validator_validate_send_ok() {
        let v = MessagingValidator::default();
        assert!(v.validate_send(&sample_send_request()).is_ok());
    }

    #[test]
    fn validator_validate_send_empty_to() {
        let v = MessagingValidator::default();
        let req = SendMessageRequest {
            to: String::new(),
            subject: "hi".into(),
            body: "hello".into(),
        };
        assert_eq!(
            v.validate_send(&req).unwrap_err(),
            MessagingValidationError::EmptyRecipient
        );
    }

    #[test]
    fn validator_validate_send_empty_subject() {
        let v = MessagingValidator::default();
        let req = SendMessageRequest {
            to: "user".into(),
            subject: String::new(),
            body: "hello".into(),
        };
        assert_eq!(
            v.validate_send(&req).unwrap_err(),
            MessagingValidationError::EmptySubject
        );
    }

    #[test]
    fn validator_validate_send_subject_too_long() {
        let v = MessagingValidator::default();
        let req = SendMessageRequest {
            to: "user".into(),
            subject: "s".repeat(101),
            body: "body".into(),
        };
        assert!(matches!(
            v.validate_send(&req).unwrap_err(),
            MessagingValidationError::SubjectTooLong { .. }
        ));
    }

    #[test]
    fn validator_validate_send_empty_body() {
        let v = MessagingValidator::default();
        let req = SendMessageRequest {
            to: "user".into(),
            subject: "sub".into(),
            body: String::new(),
        };
        assert_eq!(
            v.validate_send(&req).unwrap_err(),
            MessagingValidationError::EmptyBody
        );
    }

    #[test]
    fn validator_validate_send_body_too_long() {
        let v = MessagingValidator::default();
        let req = SendMessageRequest {
            to: "user".into(),
            subject: "sub".into(),
            body: "b".repeat(10_001),
        };
        assert!(matches!(
            v.validate_send(&req).unwrap_err(),
            MessagingValidationError::BodyTooLong { .. }
        ));
    }

    #[test]
    fn validator_custom_limits() {
        let v = MessagingValidator {
            max_subject_length: 50,
            max_body_length: 500,
            max_mark_read_batch: 10,
        };
        let req = SendMessageRequest {
            to: "user".into(),
            subject: "s".repeat(51),
            body: "ok".into(),
        };
        match v.validate_send(&req).unwrap_err() {
            MessagingValidationError::SubjectTooLong { max, got } => {
                assert_eq!(max, 50);
                assert_eq!(got, 51);
            }
            other => panic!("expected SubjectTooLong, got {other:?}"),
        }
    }

    #[test]
    fn validator_custom_body_limit() {
        let v = MessagingValidator {
            max_subject_length: 100,
            max_body_length: 200,
            max_mark_read_batch: 25,
        };
        let req = SendMessageRequest {
            to: "user".into(),
            subject: "sub".into(),
            body: "b".repeat(201),
        };
        match v.validate_send(&req).unwrap_err() {
            MessagingValidationError::BodyTooLong { max, got } => {
                assert_eq!(max, 200);
                assert_eq!(got, 201);
            }
            other => panic!("expected BodyTooLong, got {other:?}"),
        }
    }

    #[test]
    fn validator_validate_mark_read_ok() {
        let v = MessagingValidator::default();
        let req = MarkReadRequest {
            thing_ids: vec!["t4_abc".into()],
        };
        assert!(v.validate_mark_read(&req).is_ok());
    }

    #[test]
    fn validator_validate_mark_read_empty() {
        let v = MessagingValidator::default();
        let req = MarkReadRequest {
            thing_ids: vec![],
        };
        assert_eq!(
            v.validate_mark_read(&req).unwrap_err(),
            MessagingValidationError::EmptyBatch
        );
    }

    #[test]
    fn validator_validate_mark_read_too_large() {
        let v = MessagingValidator::default();
        let ids: Vec<String> = (0..26).map(|i| format!("t4_{i}")).collect();
        let req = MarkReadRequest { thing_ids: ids };
        match v.validate_mark_read(&req).unwrap_err() {
            MessagingValidationError::BatchTooLarge { max, got } => {
                assert_eq!(max, 25);
                assert_eq!(got, 26);
            }
            other => panic!("expected BatchTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn validator_validate_mark_read_exact_25() {
        let v = MessagingValidator::default();
        let ids: Vec<String> = (0..25).map(|i| format!("t4_{i}")).collect();
        let req = MarkReadRequest { thing_ids: ids };
        assert!(v.validate_mark_read(&req).is_ok());
    }

    #[test]
    fn validator_validate_mark_read_invalid_id() {
        let v = MessagingValidator::default();
        let req = MarkReadRequest {
            thing_ids: vec!["not_valid".into()],
        };
        assert!(matches!(
            v.validate_mark_read(&req).unwrap_err(),
            MessagingValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn validator_validate_query_ok() {
        let v = MessagingValidator::default();
        let q = InboxQuery::new();
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_validate_query_limit_100() {
        let v = MessagingValidator::default();
        let q = InboxQuery::new().with_limit(100);
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_validate_query_limit_over() {
        let v = MessagingValidator::default();
        let mut q = InboxQuery::new();
        q.limit = 101; // bypass builder clamp
        assert!(matches!(
            v.validate_query(&q).unwrap_err(),
            MessagingValidationError::BatchTooLarge { .. }
        ));
    }

    #[test]
    fn validator_clone() {
        let v = MessagingValidator {
            max_subject_length: 50,
            max_body_length: 500,
            max_mark_read_batch: 10,
        };
        #[allow(clippy::redundant_clone)]
        let v2 = v.clone();
        assert_eq!(v2.max_subject_length, 50);
    }

    #[test]
    fn validator_debug() {
        let v = MessagingValidator::default();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("max_subject_length"));
    }

    #[test]
    fn validator_serialize_roundtrip() {
        let v = MessagingValidator {
            max_subject_length: 80,
            max_body_length: 5000,
            max_mark_read_batch: 15,
        };
        let json = serde_json::to_value(&v).unwrap();
        let back: MessagingValidator = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_subject_length, 80);
        assert_eq!(back.max_body_length, 5000);
        assert_eq!(back.max_mark_read_batch, 15);
    }

    // ── MessagingValidationError ───────────────────────────────────────

    #[test]
    fn validation_error_display_empty_recipient() {
        assert_eq!(
            MessagingValidationError::EmptyRecipient.to_string(),
            "recipient must not be empty"
        );
    }

    #[test]
    fn validation_error_display_empty_subject() {
        assert_eq!(
            MessagingValidationError::EmptySubject.to_string(),
            "subject must not be empty"
        );
    }

    #[test]
    fn validation_error_display_subject_too_long() {
        let e = MessagingValidationError::SubjectTooLong { max: 100, got: 150 };
        assert_eq!(e.to_string(), "subject too long (150 > 100 chars)");
    }

    #[test]
    fn validation_error_display_empty_body() {
        assert_eq!(
            MessagingValidationError::EmptyBody.to_string(),
            "body must not be empty"
        );
    }

    #[test]
    fn validation_error_display_body_too_long() {
        let e = MessagingValidationError::BodyTooLong { max: 10_000, got: 10_001 };
        assert_eq!(e.to_string(), "body too long (10001 > 10000 chars)");
    }

    #[test]
    fn validation_error_display_blocked_recipient() {
        let e = MessagingValidationError::BlockedRecipient {
            username: "spammer".into(),
        };
        assert_eq!(e.to_string(), "recipient 'spammer' is blocked");
    }

    #[test]
    fn validation_error_display_empty_batch() {
        assert_eq!(
            MessagingValidationError::EmptyBatch.to_string(),
            "thing_ids must not be empty"
        );
    }

    #[test]
    fn validation_error_display_batch_too_large() {
        let e = MessagingValidationError::BatchTooLarge { max: 25, got: 30 };
        assert_eq!(e.to_string(), "batch too large (30 > 25)");
    }

    #[test]
    fn validation_error_display_invalid_thing_id() {
        let e = MessagingValidationError::InvalidThingId {
            id: "bad_id".into(),
        };
        assert_eq!(e.to_string(), "invalid Reddit fullname: 'bad_id'");
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            MessagingValidationError::EmptyRecipient,
            MessagingValidationError::EmptyRecipient
        );
        assert_ne!(
            MessagingValidationError::EmptyRecipient,
            MessagingValidationError::EmptySubject
        );
    }

    #[test]
    fn validation_error_clone() {
        let e = MessagingValidationError::SubjectTooLong { max: 100, got: 200 };
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2, MessagingValidationError::SubjectTooLong { max: 100, got: 200 });
    }

    #[test]
    fn validation_error_debug() {
        let e = MessagingValidationError::InvalidThingId { id: "xxx".into() };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("xxx"));
    }

    #[test]
    fn validation_error_serialize_roundtrip() {
        let errors = vec![
            MessagingValidationError::EmptyRecipient,
            MessagingValidationError::EmptySubject,
            MessagingValidationError::SubjectTooLong { max: 100, got: 200 },
            MessagingValidationError::EmptyBody,
            MessagingValidationError::BodyTooLong { max: 10_000, got: 20_000 },
            MessagingValidationError::BlockedRecipient { username: "x".into() },
            MessagingValidationError::EmptyBatch,
            MessagingValidationError::BatchTooLarge { max: 25, got: 50 },
            MessagingValidationError::InvalidThingId { id: "bad".into() },
        ];
        for e in errors {
            let json = serde_json::to_value(&e).unwrap();
            let back: MessagingValidationError = serde_json::from_value(json).unwrap();
            assert_eq!(back, e);
        }
    }

    #[test]
    fn validation_error_is_std_error() {
        let e: &dyn std::error::Error = &MessagingValidationError::EmptyBody;
        assert!(e.to_string().contains("body"));
    }

    // ── MessagingAuditEvent ────────────────────────────────────────────

    #[test]
    fn audit_event_inbox_read() {
        let e = MessagingAuditEvent::inbox_read(1_700_000_000.0, 25, true);
        assert_eq!(e.action, MessagingAuditAction::Read);
        assert!(e.recipient.is_none());
        assert_eq!(e.message_count, 25);
        assert!(e.was_allowed);
    }

    #[test]
    fn audit_event_message_sent() {
        let e = MessagingAuditEvent::message_sent(1_700_000_000.0, "someone", true);
        assert_eq!(e.action, MessagingAuditAction::Send);
        assert_eq!(e.recipient.as_deref(), Some("someone"));
        assert_eq!(e.message_count, 1);
    }

    #[test]
    fn audit_event_mark_read() {
        let e = MessagingAuditEvent::mark_read(1_700_000_000.0, 5, true);
        assert_eq!(e.action, MessagingAuditAction::MarkRead);
        assert!(e.recipient.is_none());
        assert_eq!(e.message_count, 5);
    }

    #[test]
    fn audit_event_denied() {
        let e = MessagingAuditEvent::message_sent(1_700_000_000.0, "blocked", false);
        assert!(!e.was_allowed);
    }

    #[test]
    fn audit_event_no_body_or_subject() {
        // Verify the struct has no body/subject fields — this is a compile-time
        // guarantee, but we also check serialization.
        let e = MessagingAuditEvent::message_sent(1_700_000_000.0, "user", true);
        let json = serde_json::to_value(&e).unwrap();
        assert!(json.get("body").is_none(), "audit event must never contain body");
        assert!(
            json.get("subject").is_none(),
            "audit event must never contain subject"
        );
    }

    #[test]
    fn audit_event_clone() {
        let e = MessagingAuditEvent::inbox_read(1_700_000_000.0, 10, true);
        let cloned = e.clone();
        assert_eq!(e.message_count, cloned.message_count);
        assert_eq!(cloned.action, MessagingAuditAction::Read);
    }

    #[test]
    fn audit_event_debug() {
        let e = MessagingAuditEvent::mark_read(1_700_000_000.0, 3, true);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("MarkRead"));
    }

    #[test]
    fn audit_event_serialize_roundtrip() {
        let e = MessagingAuditEvent::message_sent(1_700_000_100.0, "target", false);
        let json = serde_json::to_value(&e).unwrap();
        let back: MessagingAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.action, MessagingAuditAction::Send);
        assert_eq!(back.recipient.as_deref(), Some("target"));
        assert!(!back.was_allowed);
    }

    #[test]
    fn audit_event_inbox_read_zero_count() {
        let e = MessagingAuditEvent::inbox_read(0.0, 0, true);
        assert_eq!(e.message_count, 0);
        assert!(e.timestamp.abs() < f64::EPSILON);
    }

    #[test]
    fn audit_event_mark_read_zero_count() {
        let e = MessagingAuditEvent::mark_read(0.0, 0, false);
        assert_eq!(e.message_count, 0);
        assert!(!e.was_allowed);
    }

    // ── MessagingAuditAction ───────────────────────────────────────────

    #[test]
    fn audit_action_eq() {
        assert_eq!(MessagingAuditAction::Read, MessagingAuditAction::Read);
        assert_ne!(MessagingAuditAction::Read, MessagingAuditAction::Send);
        assert_ne!(MessagingAuditAction::Send, MessagingAuditAction::MarkRead);
    }

    #[test]
    fn audit_action_clone() {
        let a = MessagingAuditAction::Send;
        let a2 = a;
        assert_eq!(a, a2);
    }

    #[test]
    fn audit_action_debug() {
        assert!(format!("{:?}", MessagingAuditAction::Read).contains("Read"));
        assert!(format!("{:?}", MessagingAuditAction::Send).contains("Send"));
        assert!(format!("{:?}", MessagingAuditAction::MarkRead).contains("MarkRead"));
    }

    #[test]
    fn audit_action_serialize_roundtrip() {
        for action in [
            MessagingAuditAction::Read,
            MessagingAuditAction::Send,
            MessagingAuditAction::MarkRead,
        ] {
            let json = serde_json::to_value(action).unwrap();
            let back: MessagingAuditAction = serde_json::from_value(json).unwrap();
            assert_eq!(back, action);
        }
    }

    #[test]
    fn audit_action_copy() {
        let a = MessagingAuditAction::MarkRead;
        let a2 = a;
        assert_eq!(a, a2);
    }

    // ── Integration-style tests ────────────────────────────────────────

    #[test]
    fn full_workflow_inbox_query_validate_fetch_mark_read() {
        // Build and validate query
        let query = InboxQuery::new()
            .with_limit(10)
            .with_after("t4_start");
        assert!(query.validate().is_ok());

        let validator = MessagingValidator::default();
        assert!(validator.validate_query(&query).is_ok());

        // Simulate page result
        let page = InboxPage {
            items: (0..10)
                .map(|i| InboxItem {
                    id: format!("t4_{i}"),
                    kind: InboxItemKind::Message,
                    subject: Some(format!("Msg {i}")),
                    body: format!("Body {i}"),
                    author: "sender".into(),
                    subreddit: None,
                    created_utc: 1_700_000_000.0 + f64::from(i),
                    new: true,
                    parent_id: None,
                    context: None,
                })
                .collect(),
            after: Some("t4_9".into()),
            before: Some("t4_start".into()),
            count: 10,
            has_more: true,
        };
        assert_eq!(page.items.len(), 10);
        assert!(page.has_more);

        // Mark all as read
        let ids: Vec<String> = page.items.iter().map(|i| i.id.clone()).collect();
        let mark_req = MarkReadRequest { thing_ids: ids };
        assert!(validator.validate_mark_read(&mark_req).is_ok());

        // Audit
        let audit = MessagingAuditEvent::inbox_read(1_700_000_000.0, 10, true);
        assert_eq!(audit.message_count, 10);
    }

    #[test]
    fn full_workflow_send_message_with_policy() {
        let mut policy = MessagingPolicy::new_permissive();
        policy.blocked_recipients.insert("evil_bot".into());

        // Allowed send
        let req = SendMessageRequest {
            to: "friend".into(),
            subject: "Hi!".into(),
            body: "How are you?".into(),
        };
        assert_eq!(policy.check_send(&req.to), MessagingDecision::Allow);

        let validator = MessagingValidator::default();
        assert!(validator.validate_send(&req).is_ok());

        let audit = MessagingAuditEvent::message_sent(1_700_000_000.0, &req.to, true);
        assert!(audit.was_allowed);
        assert_eq!(audit.recipient.as_deref(), Some("friend"));

        // Blocked send
        let blocked_req = SendMessageRequest {
            to: "evil_bot".into(),
            subject: "Spam".into(),
            body: "Buy stuff".into(),
        };
        assert!(matches!(
            policy.check_send(&blocked_req.to),
            MessagingDecision::Deny { .. }
        ));
        let blocked_audit =
            MessagingAuditEvent::message_sent(1_700_000_000.0, &blocked_req.to, false);
        assert!(!blocked_audit.was_allowed);
    }

    #[test]
    fn full_workflow_readonly_policy() {
        let policy = MessagingPolicy::new_readonly();

        // Read inbox is fine (policy just records the flag)
        assert!(policy.allow_read_inbox);

        // Send denied
        assert!(matches!(
            policy.check_send("anyone"),
            MessagingDecision::Deny { .. }
        ));

        // Mark read denied
        assert!(matches!(
            policy.check_mark_read(),
            MessagingDecision::Deny { .. }
        ));
    }

    #[test]
    fn send_request_validate_checks_in_order() {
        // Empty to should be detected before empty subject
        let req = SendMessageRequest {
            to: String::new(),
            subject: String::new(),
            body: String::new(),
        };
        assert_eq!(req.validate().unwrap_err(), MessagingValidationError::EmptyRecipient);
    }

    #[test]
    fn validator_validate_send_checks_in_order() {
        let v = MessagingValidator::default();
        // Empty to first
        let req = SendMessageRequest {
            to: String::new(),
            subject: String::new(),
            body: String::new(),
        };
        assert_eq!(
            v.validate_send(&req).unwrap_err(),
            MessagingValidationError::EmptyRecipient
        );
        // Then empty subject
        let req2 = SendMessageRequest {
            to: "user".into(),
            subject: String::new(),
            body: String::new(),
        };
        assert_eq!(
            v.validate_send(&req2).unwrap_err(),
            MessagingValidationError::EmptySubject
        );
        // Then empty body
        let req3 = SendMessageRequest {
            to: "user".into(),
            subject: "sub".into(),
            body: String::new(),
        };
        assert_eq!(
            v.validate_send(&req3).unwrap_err(),
            MessagingValidationError::EmptyBody
        );
    }

    #[test]
    fn mark_read_validate_single_valid() {
        let req = MarkReadRequest {
            thing_ids: vec!["t1_x".into()],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn mark_read_validate_all_types() {
        let req = MarkReadRequest {
            thing_ids: vec![
                "t1_a".into(),
                "t2_b".into(),
                "t3_c".into(),
                "t4_d".into(),
                "t5_e".into(),
                "t6_f".into(),
            ],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn inbox_item_modmail() {
        let item = InboxItem {
            id: "t4_modmail".into(),
            kind: InboxItemKind::ModMail,
            subject: Some("Mod discussion".into()),
            body: "Please review".into(),
            author: "mod_user".into(),
            subreddit: Some("moderated_sub".into()),
            created_utc: 1_700_000_400.0,
            new: true,
            parent_id: None,
            context: None,
        };
        assert_eq!(item.kind, InboxItemKind::ModMail);
        assert_eq!(item.subreddit.as_deref(), Some("moderated_sub"));
    }
}
