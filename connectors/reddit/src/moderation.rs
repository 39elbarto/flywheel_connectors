//! `Reddit` moderation actions.
//!
//! Provides types and validation for `Reddit` moderation operations including
//! post/comment approval/removal, user bans/mutes, flair management, and
//! policy-based approval gating for destructive actions.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── ModAction ───────────────────────────────────────────────────────────────

/// A moderation action that can be performed on `Reddit` content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModAction {
    /// Approve a post or comment.
    Approve,
    /// Remove a post or comment.
    Remove,
    /// Mark as spam.
    Spam,
    /// Lock a post or comment (prevent new replies).
    Lock,
    /// Unlock a post or comment.
    Unlock,
    /// Distinguish a comment as a moderator.
    Distinguish,
    /// Remove distinguish from a comment.
    Undistinguish,
    /// Sticky a post or comment.
    Sticky,
    /// Unsticky a post or comment.
    Unsticky,
    /// Set flair on a post or user.
    SetFlair,
    /// Ignore future reports on content.
    IgnoreReports,
    /// Stop ignoring reports on content.
    UnignoreReports,
}

impl ModAction {
    /// Returns the `Reddit` API string representation of this action.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Remove => "remove",
            Self::Spam => "spam",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Distinguish => "distinguish",
            Self::Undistinguish => "undistinguish",
            Self::Sticky => "sticky",
            Self::Unsticky => "unsticky",
            Self::SetFlair => "set_flair",
            Self::IgnoreReports => "ignore_reports",
            Self::UnignoreReports => "unignore_reports",
        }
    }

    /// Returns `true` if this action is destructive (high blast radius).
    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(self, Self::Remove | Self::Spam | Self::Lock)
    }

    /// Returns `true` if this action requires approval gating.
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(
            self,
            Self::Remove | Self::Spam | Self::Lock | Self::IgnoreReports
        )
    }
}

impl fmt::Display for ModAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ContentType ─────────────────────────────────────────────────────────────

/// The type of `Reddit` content targeted by a moderation action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentType {
    /// A `Reddit` post (link or self-post).
    Post,
    /// A `Reddit` comment.
    Comment,
    /// A `Reddit` user.
    User,
}

impl ContentType {
    /// Returns the `Reddit` thing prefix for this content type.
    #[must_use]
    pub const fn thing_prefix(&self) -> &'static str {
        match self {
            Self::Post => "t3_",
            Self::Comment => "t1_",
            Self::User => "t2_",
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Post => f.write_str("post"),
            Self::Comment => f.write_str("comment"),
            Self::User => f.write_str("user"),
        }
    }
}

// ── ModTarget ───────────────────────────────────────────────────────────────

/// The target of a moderation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModTarget {
    /// The `Reddit` fullname (e.g. `t3_abc123`).
    pub thing_id: String,
    /// The subreddit this target belongs to.
    pub subreddit: String,
    /// The type of content.
    pub content_type: ContentType,
}

impl ModTarget {
    /// Creates a new moderation target.
    #[must_use]
    pub fn new(
        thing_id: impl Into<String>,
        subreddit: impl Into<String>,
        content_type: ContentType,
    ) -> Self {
        Self {
            thing_id: thing_id.into(),
            subreddit: subreddit.into(),
            content_type,
        }
    }

    /// Validates that the thing ID has the correct prefix for its content type.
    #[must_use]
    pub fn has_valid_prefix(&self) -> bool {
        self.thing_id.starts_with(self.content_type.thing_prefix())
    }
}

// ── BanRequest ──────────────────────────────────────────────────────────────

/// A request to ban a user from a subreddit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRequest {
    /// The username to ban.
    pub username: String,
    /// The subreddit to ban the user from.
    pub subreddit: String,
    /// Duration in days. `None` means permanent ban.
    pub duration_days: Option<u32>,
    /// The reason for the ban (visible to other moderators).
    pub reason: String,
    /// An optional mod note (private).
    pub note: Option<String>,
    /// An optional message sent to the banned user.
    pub message: Option<String>,
}

impl BanRequest {
    /// Validates the ban request.
    ///
    /// # Errors
    ///
    /// Returns `ModValidationError` if the request is invalid.
    pub fn validate(&self) -> Result<(), ModValidationError> {
        if self.username.is_empty() {
            return Err(ModValidationError::EmptyUsername);
        }
        if self.subreddit.is_empty() {
            return Err(ModValidationError::EmptySubreddit);
        }
        if self.reason.is_empty() {
            return Err(ModValidationError::EmptyReason);
        }
        if let Some(days) = self.duration_days {
            if days == 0 || days > 999 {
                return Err(ModValidationError::InvalidDuration {
                    days,
                    reason: "duration must be between 1 and 999 days".into(),
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if this is a permanent ban.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        self.duration_days.is_none()
    }
}

// ── UnbanRequest ────────────────────────────────────────────────────────────

/// A request to unban a user from a subreddit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbanRequest {
    /// The username to unban.
    pub username: String,
    /// The subreddit to unban the user from.
    pub subreddit: String,
}

impl UnbanRequest {
    /// Validates the unban request.
    ///
    /// # Errors
    ///
    /// Returns `ModValidationError` if the request is invalid.
    pub fn validate(&self) -> Result<(), ModValidationError> {
        if self.username.is_empty() {
            return Err(ModValidationError::EmptyUsername);
        }
        if self.subreddit.is_empty() {
            return Err(ModValidationError::EmptySubreddit);
        }
        Ok(())
    }
}

// ── MuteRequest ─────────────────────────────────────────────────────────────

/// A request to mute a user in a subreddit (prevent modmail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuteRequest {
    /// The username to mute.
    pub username: String,
    /// The subreddit in which to mute the user.
    pub subreddit: String,
    /// Duration in hours. `None` defaults to 72 hours.
    pub duration_hours: Option<u32>,
}

impl MuteRequest {
    /// The default mute duration in hours.
    pub const DEFAULT_DURATION_HOURS: u32 = 72;

    /// Returns the effective mute duration in hours.
    #[must_use]
    pub const fn effective_duration_hours(&self) -> u32 {
        match self.duration_hours {
            Some(h) => h,
            None => Self::DEFAULT_DURATION_HOURS,
        }
    }

    /// Validates the mute request.
    ///
    /// # Errors
    ///
    /// Returns `ModValidationError` if the request is invalid.
    pub fn validate(&self) -> Result<(), ModValidationError> {
        if self.username.is_empty() {
            return Err(ModValidationError::EmptyUsername);
        }
        if self.subreddit.is_empty() {
            return Err(ModValidationError::EmptySubreddit);
        }
        Ok(())
    }
}

// ── FlairRequest ────────────────────────────────────────────────────────────

/// A request to set flair on a post or user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlairRequest {
    /// The `Reddit` fullname of the target.
    pub thing_id: String,
    /// The subreddit context.
    pub subreddit: String,
    /// The flair text (display label).
    pub flair_text: Option<String>,
    /// The CSS class for the flair.
    pub flair_css_class: Option<String>,
    /// A flair template ID.
    pub flair_template_id: Option<String>,
}

impl FlairRequest {
    /// Validates the flair request.
    ///
    /// # Errors
    ///
    /// Returns `ModValidationError` if the request is invalid.
    pub fn validate(&self) -> Result<(), ModValidationError> {
        if self.thing_id.is_empty() {
            return Err(ModValidationError::InvalidThingId {
                id: String::new(),
                reason: "thing_id must not be empty".into(),
            });
        }
        if self.subreddit.is_empty() {
            return Err(ModValidationError::EmptySubreddit);
        }
        if let Some(text) = &self.flair_text {
            if text.len() > ModValidator::MAX_FLAIR_LENGTH {
                return Err(ModValidationError::FlairTooLong {
                    length: text.len(),
                    max: ModValidator::MAX_FLAIR_LENGTH,
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if at least one flair field is set.
    #[must_use]
    pub const fn has_any_flair(&self) -> bool {
        self.flair_text.is_some()
            || self.flair_css_class.is_some()
            || self.flair_template_id.is_some()
    }
}

// ── ModActionResult ─────────────────────────────────────────────────────────

/// The result of executing a moderation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModActionResult {
    /// The action that was performed.
    pub action: ModAction,
    /// The target of the action.
    pub target: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// An error message if the action failed.
    pub error_message: Option<String>,
    /// When the action was performed (Unix timestamp).
    pub timestamp: u64,
}

impl ModActionResult {
    /// Creates a successful result.
    #[must_use]
    pub fn success(action: ModAction, target: impl Into<String>, timestamp: u64) -> Self {
        Self {
            action,
            target: target.into(),
            success: true,
            error_message: None,
            timestamp,
        }
    }

    /// Creates a failed result.
    #[must_use]
    pub fn failure(
        action: ModAction,
        target: impl Into<String>,
        error: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            action,
            target: target.into(),
            success: false,
            error_message: Some(error.into()),
            timestamp,
        }
    }
}

// ── ModDecision ─────────────────────────────────────────────────────────────

/// The outcome of checking a moderation action against the mod policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModDecision {
    /// The action is allowed to proceed.
    Allow,
    /// The action is denied.
    Deny {
        /// The reason for denial.
        reason: String,
    },
    /// The action requires explicit approval before proceeding.
    RequireApproval {
        /// Why approval is required.
        reason: String,
    },
}

impl ModDecision {
    /// Returns `true` if the decision allows the action.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision denies the action.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns `true` if the decision requires approval.
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(self, Self::RequireApproval { .. })
    }
}

// ── ModPolicy ───────────────────────────────────────────────────────────────

/// Policy configuration for moderation actions.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModPolicy {
    /// Whether approve actions are allowed.
    pub allow_approve: bool,
    /// Whether remove/spam actions are allowed.
    pub allow_remove: bool,
    /// Whether ban/mute actions are allowed.
    pub allow_ban: bool,
    /// Whether flair actions are allowed.
    pub allow_flair: bool,
    /// Whether ban actions require explicit approval.
    pub require_approval_for_ban: bool,
    /// Whether remove actions require explicit approval.
    pub require_approval_for_remove: bool,
    /// Maximum ban duration in days (if set).
    pub max_ban_duration_days: Option<u32>,
    /// Users that are protected from bans/removes.
    pub protected_users: HashSet<String>,
}

impl ModPolicy {
    /// Creates a policy that allows all moderation actions.
    #[must_use]
    pub fn new_full() -> Self {
        Self {
            allow_approve: true,
            allow_remove: true,
            allow_ban: true,
            allow_flair: true,
            require_approval_for_ban: true,
            require_approval_for_remove: true,
            max_ban_duration_days: None,
            protected_users: HashSet::new(),
        }
    }

    /// Creates a read-only policy that denies all moderation actions.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_approve: false,
            allow_remove: false,
            allow_ban: false,
            allow_flair: false,
            require_approval_for_ban: false,
            require_approval_for_remove: false,
            max_ban_duration_days: None,
            protected_users: HashSet::new(),
        }
    }

    /// Checks whether a moderation action is allowed by this policy.
    #[must_use]
    pub fn check_action(&self, action: &ModAction) -> ModDecision {
        match action {
            ModAction::Approve => {
                if self.allow_approve {
                    ModDecision::Allow
                } else {
                    ModDecision::Deny {
                        reason: "approve actions are not permitted by policy".into(),
                    }
                }
            }
            ModAction::Remove | ModAction::Spam => {
                if !self.allow_remove {
                    return ModDecision::Deny {
                        reason: "remove/spam actions are not permitted by policy".into(),
                    };
                }
                if self.require_approval_for_remove {
                    ModDecision::RequireApproval {
                        reason: "remove/spam actions require approval".into(),
                    }
                } else {
                    ModDecision::Allow
                }
            }
            ModAction::SetFlair => {
                if self.allow_flair {
                    ModDecision::Allow
                } else {
                    ModDecision::Deny {
                        reason: "flair actions are not permitted by policy".into(),
                    }
                }
            }
            ModAction::Lock | ModAction::IgnoreReports => {
                if !self.allow_remove {
                    return ModDecision::Deny {
                        reason: "destructive actions are not permitted by policy".into(),
                    };
                }
                if self.require_approval_for_remove {
                    ModDecision::RequireApproval {
                        reason: "destructive actions require approval".into(),
                    }
                } else {
                    ModDecision::Allow
                }
            }
            ModAction::Unlock
            | ModAction::Distinguish
            | ModAction::Undistinguish
            | ModAction::Sticky
            | ModAction::Unsticky
            | ModAction::UnignoreReports => {
                if self.allow_approve {
                    ModDecision::Allow
                } else {
                    ModDecision::Deny {
                        reason: "non-destructive actions require at least approve permission"
                            .into(),
                    }
                }
            }
        }
    }

    /// Checks whether a ban request is allowed by this policy.
    #[must_use]
    pub fn check_ban(&self, request: &BanRequest) -> ModDecision {
        if !self.allow_ban {
            return ModDecision::Deny {
                reason: "ban actions are not permitted by policy".into(),
            };
        }
        if self.protected_users.contains(&request.username) {
            return ModDecision::Deny {
                reason: format!("user '{}' is protected by policy", request.username),
            };
        }
        if let Some(max_days) = self.max_ban_duration_days {
            if let Some(days) = request.duration_days {
                if days > max_days {
                    return ModDecision::Deny {
                        reason: format!("ban duration {days} days exceeds maximum {max_days} days"),
                    };
                }
            } else {
                // Permanent ban exceeds any max
                return ModDecision::Deny {
                    reason: format!("permanent bans not allowed; maximum is {max_days} days"),
                };
            }
        }
        if self.require_approval_for_ban {
            ModDecision::RequireApproval {
                reason: "ban actions require approval".into(),
            }
        } else {
            ModDecision::Allow
        }
    }
}

// ── ModValidator ────────────────────────────────────────────────────────────

/// Validates moderation request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModValidator {
    /// Maximum length of a ban reason.
    pub max_ban_reason_length: usize,
    /// Maximum length of a mod note.
    pub max_note_length: usize,
    /// Maximum length of flair text.
    pub max_flair_length: usize,
}

impl ModValidator {
    /// Default maximum ban reason length.
    pub const MAX_BAN_REASON_LENGTH: usize = 500;
    /// Default maximum mod note length.
    pub const MAX_NOTE_LENGTH: usize = 300;
    /// Default maximum flair text length.
    pub const MAX_FLAIR_LENGTH: usize = 64;

    /// Creates a validator with default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_ban_reason_length: Self::MAX_BAN_REASON_LENGTH,
            max_note_length: Self::MAX_NOTE_LENGTH,
            max_flair_length: Self::MAX_FLAIR_LENGTH,
        }
    }

    /// Validates a ban request against this validator's limits.
    ///
    /// # Errors
    ///
    /// Returns `ModValidationError` if the request exceeds limits.
    pub fn validate_ban(&self, request: &BanRequest) -> Result<(), ModValidationError> {
        request.validate()?;
        if request.reason.len() > self.max_ban_reason_length {
            return Err(ModValidationError::ReasonTooLong {
                length: request.reason.len(),
                max: self.max_ban_reason_length,
            });
        }
        if let Some(note) = &request.note {
            if note.len() > self.max_note_length {
                return Err(ModValidationError::NoteTooLong {
                    length: note.len(),
                    max: self.max_note_length,
                });
            }
        }
        Ok(())
    }

    /// Validates a flair request against this validator's limits.
    ///
    /// # Errors
    ///
    /// Returns `ModValidationError` if the request exceeds limits.
    pub fn validate_flair(&self, request: &FlairRequest) -> Result<(), ModValidationError> {
        if request.thing_id.is_empty() {
            return Err(ModValidationError::InvalidThingId {
                id: String::new(),
                reason: "thing_id must not be empty".into(),
            });
        }
        if request.subreddit.is_empty() {
            return Err(ModValidationError::EmptySubreddit);
        }
        if let Some(text) = &request.flair_text {
            if text.len() > self.max_flair_length {
                return Err(ModValidationError::FlairTooLong {
                    length: text.len(),
                    max: self.max_flair_length,
                });
            }
        }
        Ok(())
    }
}

impl Default for ModValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── ModValidationError ──────────────────────────────────────────────────────

/// Errors that can occur during moderation request validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModValidationError {
    /// Username is empty.
    EmptyUsername,
    /// Subreddit is empty.
    EmptySubreddit,
    /// Reason is empty.
    EmptyReason,
    /// Reason exceeds maximum length.
    ReasonTooLong {
        /// The actual length.
        length: usize,
        /// The maximum allowed.
        max: usize,
    },
    /// Note exceeds maximum length.
    NoteTooLong {
        /// The actual length.
        length: usize,
        /// The maximum allowed.
        max: usize,
    },
    /// Flair text exceeds maximum length.
    FlairTooLong {
        /// The actual length.
        length: usize,
        /// The maximum allowed.
        max: usize,
    },
    /// Ban duration is invalid.
    InvalidDuration {
        /// The invalid duration in days.
        days: u32,
        /// Why it's invalid.
        reason: String,
    },
    /// User is protected and cannot be moderated.
    ProtectedUser {
        /// The protected username.
        username: String,
    },
    /// The thing ID is invalid.
    InvalidThingId {
        /// The invalid ID.
        id: String,
        /// Why it's invalid.
        reason: String,
    },
}

impl fmt::Display for ModValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUsername => write!(f, "username must not be empty"),
            Self::EmptySubreddit => write!(f, "subreddit must not be empty"),
            Self::EmptyReason => write!(f, "reason must not be empty"),
            Self::ReasonTooLong { length, max } => {
                write!(f, "reason too long ({length} chars, max {max})")
            }
            Self::NoteTooLong { length, max } => {
                write!(f, "note too long ({length} chars, max {max})")
            }
            Self::FlairTooLong { length, max } => {
                write!(f, "flair text too long ({length} chars, max {max})")
            }
            Self::InvalidDuration { days, reason } => {
                write!(f, "invalid ban duration ({days} days): {reason}")
            }
            Self::ProtectedUser { username } => {
                write!(f, "user '{username}' is protected")
            }
            Self::InvalidThingId { id, reason } => {
                write!(f, "invalid thing ID '{id}': {reason}")
            }
        }
    }
}

impl std::error::Error for ModValidationError {}

// ── ModAuditEvent ───────────────────────────────────────────────────────────

/// An audit trail entry for a moderation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModAuditEvent {
    /// Unix timestamp of the event.
    pub timestamp: u64,
    /// The action that was performed or attempted.
    pub action: String,
    /// The target's `Reddit` fullname.
    pub target_id: String,
    /// The subreddit context.
    pub subreddit: String,
    /// The moderator who performed the action (if known).
    pub moderator: Option<String>,
    /// Human-readable details about the event.
    pub details: String,
    /// Whether the action was actually executed.
    pub was_allowed: bool,
}

impl ModAuditEvent {
    /// Creates a new audit event.
    #[must_use]
    pub fn new(
        timestamp: u64,
        action: impl Into<String>,
        target_id: impl Into<String>,
        subreddit: impl Into<String>,
        moderator: Option<String>,
        details: impl Into<String>,
        was_allowed: bool,
    ) -> Self {
        Self {
            timestamp,
            action: action.into(),
            target_id: target_id.into(),
            subreddit: subreddit.into(),
            moderator,
            details: details.into(),
            was_allowed,
        }
    }

    /// Creates an audit event for a denied action.
    #[must_use]
    pub fn denied(
        timestamp: u64,
        action: &ModAction,
        target_id: impl Into<String>,
        subreddit: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp,
            action: action.as_str().to_owned(),
            target_id: target_id.into(),
            subreddit: subreddit.into(),
            moderator: None,
            details: format!("Denied: {}", reason.into()),
            was_allowed: false,
        }
    }

    /// Creates an audit event for an allowed action.
    #[must_use]
    pub fn allowed(
        timestamp: u64,
        action: &ModAction,
        target_id: impl Into<String>,
        subreddit: impl Into<String>,
        moderator: Option<String>,
    ) -> Self {
        Self {
            timestamp,
            action: action.as_str().to_owned(),
            target_id: target_id.into(),
            subreddit: subreddit.into(),
            moderator,
            details: "Action executed successfully".to_owned(),
            was_allowed: true,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ModAction ───────────────────────────────────────────────────

    #[test]
    fn mod_action_as_str() {
        assert_eq!(ModAction::Approve.as_str(), "approve");
        assert_eq!(ModAction::Remove.as_str(), "remove");
        assert_eq!(ModAction::Spam.as_str(), "spam");
        assert_eq!(ModAction::Lock.as_str(), "lock");
        assert_eq!(ModAction::Unlock.as_str(), "unlock");
        assert_eq!(ModAction::Distinguish.as_str(), "distinguish");
        assert_eq!(ModAction::Undistinguish.as_str(), "undistinguish");
        assert_eq!(ModAction::Sticky.as_str(), "sticky");
        assert_eq!(ModAction::Unsticky.as_str(), "unsticky");
        assert_eq!(ModAction::SetFlair.as_str(), "set_flair");
        assert_eq!(ModAction::IgnoreReports.as_str(), "ignore_reports");
        assert_eq!(ModAction::UnignoreReports.as_str(), "unignore_reports");
    }

    #[test]
    fn mod_action_is_destructive() {
        assert!(ModAction::Remove.is_destructive());
        assert!(ModAction::Spam.is_destructive());
        assert!(ModAction::Lock.is_destructive());
        assert!(!ModAction::Approve.is_destructive());
        assert!(!ModAction::Unlock.is_destructive());
        assert!(!ModAction::Distinguish.is_destructive());
        assert!(!ModAction::SetFlair.is_destructive());
        assert!(!ModAction::Sticky.is_destructive());
        assert!(!ModAction::UnignoreReports.is_destructive());
    }

    #[test]
    fn mod_action_requires_approval() {
        assert!(ModAction::Remove.requires_approval());
        assert!(ModAction::Spam.requires_approval());
        assert!(ModAction::Lock.requires_approval());
        assert!(ModAction::IgnoreReports.requires_approval());
        assert!(!ModAction::Approve.requires_approval());
        assert!(!ModAction::Unlock.requires_approval());
        assert!(!ModAction::Distinguish.requires_approval());
        assert!(!ModAction::Undistinguish.requires_approval());
        assert!(!ModAction::Sticky.requires_approval());
        assert!(!ModAction::Unsticky.requires_approval());
        assert!(!ModAction::SetFlair.requires_approval());
        assert!(!ModAction::UnignoreReports.requires_approval());
    }

    #[test]
    fn mod_action_display() {
        assert_eq!(ModAction::Approve.to_string(), "approve");
        assert_eq!(ModAction::Remove.to_string(), "remove");
        assert_eq!(ModAction::IgnoreReports.to_string(), "ignore_reports");
    }

    #[test]
    fn mod_action_debug() {
        let dbg = format!("{:?}", ModAction::Approve);
        assert!(dbg.contains("Approve"));
    }

    #[test]
    fn mod_action_clone() {
        let a = ModAction::Remove;
        #[allow(clippy::redundant_clone)]
        let b = a.clone();
        assert_eq!(b, ModAction::Remove);
    }

    #[test]
    fn mod_action_eq() {
        assert_eq!(ModAction::Lock, ModAction::Lock);
        assert_ne!(ModAction::Lock, ModAction::Unlock);
    }

    #[test]
    fn mod_action_hash() {
        let mut set = HashSet::new();
        set.insert(ModAction::Approve);
        set.insert(ModAction::Remove);
        set.insert(ModAction::Approve);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn mod_action_serde_roundtrip() {
        let action = ModAction::Spam;
        let json = serde_json::to_string(&action).unwrap();
        let back: ModAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ModAction::Spam);
    }

    #[test]
    fn mod_action_all_variants_as_str() {
        let actions = [
            ModAction::Approve,
            ModAction::Remove,
            ModAction::Spam,
            ModAction::Lock,
            ModAction::Unlock,
            ModAction::Distinguish,
            ModAction::Undistinguish,
            ModAction::Sticky,
            ModAction::Unsticky,
            ModAction::SetFlair,
            ModAction::IgnoreReports,
            ModAction::UnignoreReports,
        ];
        for a in &actions {
            assert!(!a.as_str().is_empty());
        }
    }

    // ── ContentType ─────────────────────────────────────────────────

    #[test]
    fn content_type_thing_prefix() {
        assert_eq!(ContentType::Post.thing_prefix(), "t3_");
        assert_eq!(ContentType::Comment.thing_prefix(), "t1_");
        assert_eq!(ContentType::User.thing_prefix(), "t2_");
    }

    #[test]
    fn content_type_display() {
        assert_eq!(ContentType::Post.to_string(), "post");
        assert_eq!(ContentType::Comment.to_string(), "comment");
        assert_eq!(ContentType::User.to_string(), "user");
    }

    #[test]
    fn content_type_serde_roundtrip() {
        let ct = ContentType::Comment;
        let json = serde_json::to_string(&ct).unwrap();
        let back: ContentType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ContentType::Comment);
    }

    #[test]
    fn content_type_clone() {
        let ct = ContentType::Post;
        #[allow(clippy::redundant_clone)]
        let ct2 = ct.clone();
        assert_eq!(ct2, ContentType::Post);
    }

    #[test]
    fn content_type_eq() {
        assert_eq!(ContentType::User, ContentType::User);
        assert_ne!(ContentType::Post, ContentType::Comment);
    }

    #[test]
    fn content_type_debug() {
        let dbg = format!("{:?}", ContentType::Post);
        assert!(dbg.contains("Post"));
    }

    // ── ModTarget ───────────────────────────────────────────────────

    #[test]
    fn mod_target_new() {
        let t = ModTarget::new("t3_abc", "rust", ContentType::Post);
        assert_eq!(t.thing_id, "t3_abc");
        assert_eq!(t.subreddit, "rust");
        assert_eq!(t.content_type, ContentType::Post);
    }

    #[test]
    fn mod_target_valid_prefix_post() {
        let t = ModTarget::new("t3_abc", "test", ContentType::Post);
        assert!(t.has_valid_prefix());
    }

    #[test]
    fn mod_target_valid_prefix_comment() {
        let t = ModTarget::new("t1_xyz", "test", ContentType::Comment);
        assert!(t.has_valid_prefix());
    }

    #[test]
    fn mod_target_valid_prefix_user() {
        let t = ModTarget::new("t2_user", "test", ContentType::User);
        assert!(t.has_valid_prefix());
    }

    #[test]
    fn mod_target_invalid_prefix() {
        let t = ModTarget::new("t1_abc", "test", ContentType::Post);
        assert!(!t.has_valid_prefix());
    }

    #[test]
    fn mod_target_clone() {
        let t = ModTarget::new("t3_abc", "rust", ContentType::Post);
        #[allow(clippy::redundant_clone)]
        let t2 = t.clone();
        assert_eq!(t2.thing_id, "t3_abc");
    }

    #[test]
    fn mod_target_debug() {
        let t = ModTarget::new("t3_dbg", "rust", ContentType::Post);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("t3_dbg"));
        assert!(dbg.contains("rust"));
    }

    #[test]
    fn mod_target_serde_roundtrip() {
        let t = ModTarget::new("t3_ser", "test", ContentType::Post);
        let json = serde_json::to_string(&t).unwrap();
        let back: ModTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thing_id, "t3_ser");
        assert_eq!(back.subreddit, "test");
    }

    // ── BanRequest ──────────────────────────────────────────────────

    fn valid_ban() -> BanRequest {
        BanRequest {
            username: "spammer".into(),
            subreddit: "rust".into(),
            duration_days: Some(30),
            reason: "Spamming".into(),
            note: Some("Repeated violations".into()),
            message: Some("You have been banned".into()),
        }
    }

    #[test]
    fn ban_request_validate_ok() {
        assert!(valid_ban().validate().is_ok());
    }

    #[test]
    fn ban_request_validate_empty_username() {
        let mut r = valid_ban();
        r.username = String::new();
        assert_eq!(r.validate().unwrap_err(), ModValidationError::EmptyUsername);
    }

    #[test]
    fn ban_request_validate_empty_subreddit() {
        let mut r = valid_ban();
        r.subreddit = String::new();
        assert_eq!(
            r.validate().unwrap_err(),
            ModValidationError::EmptySubreddit
        );
    }

    #[test]
    fn ban_request_validate_empty_reason() {
        let mut r = valid_ban();
        r.reason = String::new();
        assert_eq!(r.validate().unwrap_err(), ModValidationError::EmptyReason);
    }

    #[test]
    fn ban_request_validate_duration_zero() {
        let mut r = valid_ban();
        r.duration_days = Some(0);
        assert!(matches!(
            r.validate().unwrap_err(),
            ModValidationError::InvalidDuration { days: 0, .. }
        ));
    }

    #[test]
    fn ban_request_validate_duration_too_high() {
        let mut r = valid_ban();
        r.duration_days = Some(1000);
        assert!(matches!(
            r.validate().unwrap_err(),
            ModValidationError::InvalidDuration { days: 1000, .. }
        ));
    }

    #[test]
    fn ban_request_validate_duration_999() {
        let mut r = valid_ban();
        r.duration_days = Some(999);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn ban_request_permanent() {
        let mut r = valid_ban();
        r.duration_days = None;
        assert!(r.is_permanent());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn ban_request_not_permanent() {
        let r = valid_ban();
        assert!(!r.is_permanent());
    }

    #[test]
    fn ban_request_clone() {
        let r = valid_ban();
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.username, "spammer");
    }

    #[test]
    fn ban_request_debug() {
        let dbg = format!("{:?}", valid_ban());
        assert!(dbg.contains("spammer"));
    }

    #[test]
    fn ban_request_serde_roundtrip() {
        let r = valid_ban();
        let json = serde_json::to_string(&r).unwrap();
        let back: BanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.username, "spammer");
        assert_eq!(back.duration_days, Some(30));
    }

    #[test]
    fn ban_request_serde_no_optional() {
        let r = BanRequest {
            username: "user".into(),
            subreddit: "sub".into(),
            duration_days: None,
            reason: "reason".into(),
            note: None,
            message: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: BanRequest = serde_json::from_str(&json).unwrap();
        assert!(back.note.is_none());
        assert!(back.message.is_none());
        assert!(back.duration_days.is_none());
    }

    // ── UnbanRequest ────────────────────────────────────────────────

    #[test]
    fn unban_request_validate_ok() {
        let r = UnbanRequest {
            username: "user".into(),
            subreddit: "rust".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn unban_request_validate_empty_username() {
        let r = UnbanRequest {
            username: String::new(),
            subreddit: "rust".into(),
        };
        assert_eq!(r.validate().unwrap_err(), ModValidationError::EmptyUsername);
    }

    #[test]
    fn unban_request_validate_empty_subreddit() {
        let r = UnbanRequest {
            username: "user".into(),
            subreddit: String::new(),
        };
        assert_eq!(
            r.validate().unwrap_err(),
            ModValidationError::EmptySubreddit
        );
    }

    #[test]
    fn unban_request_clone() {
        let r = UnbanRequest {
            username: "u".into(),
            subreddit: "s".into(),
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.username, "u");
    }

    #[test]
    fn unban_request_serde_roundtrip() {
        let r = UnbanRequest {
            username: "user1".into(),
            subreddit: "sub1".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: UnbanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.username, "user1");
    }

    // ── MuteRequest ─────────────────────────────────────────────────

    #[test]
    fn mute_request_default_duration() {
        let r = MuteRequest {
            username: "user".into(),
            subreddit: "sub".into(),
            duration_hours: None,
        };
        assert_eq!(r.effective_duration_hours(), 72);
    }

    #[test]
    fn mute_request_custom_duration() {
        let r = MuteRequest {
            username: "user".into(),
            subreddit: "sub".into(),
            duration_hours: Some(24),
        };
        assert_eq!(r.effective_duration_hours(), 24);
    }

    #[test]
    fn mute_request_validate_ok() {
        let r = MuteRequest {
            username: "user".into(),
            subreddit: "sub".into(),
            duration_hours: None,
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn mute_request_validate_empty_username() {
        let r = MuteRequest {
            username: String::new(),
            subreddit: "sub".into(),
            duration_hours: None,
        };
        assert_eq!(r.validate().unwrap_err(), ModValidationError::EmptyUsername);
    }

    #[test]
    fn mute_request_validate_empty_subreddit() {
        let r = MuteRequest {
            username: "user".into(),
            subreddit: String::new(),
            duration_hours: None,
        };
        assert_eq!(
            r.validate().unwrap_err(),
            ModValidationError::EmptySubreddit
        );
    }

    #[test]
    fn mute_request_clone() {
        let r = MuteRequest {
            username: "u".into(),
            subreddit: "s".into(),
            duration_hours: Some(48),
        };
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.duration_hours, Some(48));
    }

    #[test]
    fn mute_request_serde_roundtrip() {
        let r = MuteRequest {
            username: "user".into(),
            subreddit: "sub".into(),
            duration_hours: Some(168),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MuteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.duration_hours, Some(168));
    }

    // ── FlairRequest ────────────────────────────────────────────────

    fn valid_flair() -> FlairRequest {
        FlairRequest {
            thing_id: "t3_abc".into(),
            subreddit: "rust".into(),
            flair_text: Some("Discussion".into()),
            flair_css_class: Some("discussion".into()),
            flair_template_id: None,
        }
    }

    #[test]
    fn flair_request_validate_ok() {
        assert!(valid_flair().validate().is_ok());
    }

    #[test]
    fn flair_request_validate_empty_thing_id() {
        let mut r = valid_flair();
        r.thing_id = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            ModValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn flair_request_validate_empty_subreddit() {
        let mut r = valid_flair();
        r.subreddit = String::new();
        assert_eq!(
            r.validate().unwrap_err(),
            ModValidationError::EmptySubreddit
        );
    }

    #[test]
    fn flair_request_validate_too_long() {
        let mut r = valid_flair();
        r.flair_text = Some("x".repeat(65));
        assert!(matches!(
            r.validate().unwrap_err(),
            ModValidationError::FlairTooLong {
                length: 65,
                max: 64
            }
        ));
    }

    #[test]
    fn flair_request_has_any_flair() {
        assert!(valid_flair().has_any_flair());
    }

    #[test]
    fn flair_request_no_flair() {
        let r = FlairRequest {
            thing_id: "t3_abc".into(),
            subreddit: "rust".into(),
            flair_text: None,
            flair_css_class: None,
            flair_template_id: None,
        };
        assert!(!r.has_any_flair());
    }

    #[test]
    fn flair_request_only_template() {
        let r = FlairRequest {
            thing_id: "t3_abc".into(),
            subreddit: "rust".into(),
            flair_text: None,
            flair_css_class: None,
            flair_template_id: Some("tmpl_1".into()),
        };
        assert!(r.has_any_flair());
    }

    #[test]
    fn flair_request_clone() {
        let r = valid_flair();
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert_eq!(r2.thing_id, "t3_abc");
    }

    #[test]
    fn flair_request_serde_roundtrip() {
        let r = valid_flair();
        let json = serde_json::to_string(&r).unwrap();
        let back: FlairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.flair_text, Some("Discussion".into()));
    }

    #[test]
    fn flair_request_validate_max_boundary() {
        let mut r = valid_flair();
        r.flair_text = Some("x".repeat(64));
        assert!(r.validate().is_ok());
    }

    // ── ModActionResult ─────────────────────────────────────────────

    #[test]
    fn mod_action_result_success() {
        let r = ModActionResult::success(ModAction::Approve, "t3_abc", 1000);
        assert!(r.success);
        assert!(r.error_message.is_none());
        assert_eq!(r.timestamp, 1000);
        assert_eq!(r.target, "t3_abc");
    }

    #[test]
    fn mod_action_result_failure() {
        let r = ModActionResult::failure(ModAction::Remove, "t3_abc", "denied", 2000);
        assert!(!r.success);
        assert_eq!(r.error_message, Some("denied".into()));
        assert_eq!(r.timestamp, 2000);
    }

    #[test]
    fn mod_action_result_clone() {
        let r = ModActionResult::success(ModAction::Lock, "t3_x", 100);
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert!(r2.success);
    }

    #[test]
    fn mod_action_result_debug() {
        let r = ModActionResult::success(ModAction::Approve, "t3_dbg", 0);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Approve"));
    }

    #[test]
    fn mod_action_result_serde_roundtrip() {
        let r = ModActionResult::failure(ModAction::Spam, "t3_spam", "err", 500);
        let json = serde_json::to_string(&r).unwrap();
        let back: ModActionResult = serde_json::from_str(&json).unwrap();
        assert!(!back.success);
        assert_eq!(back.error_message, Some("err".into()));
    }

    // ── ModDecision ─────────────────────────────────────────────────

    #[test]
    fn mod_decision_allow() {
        let d = ModDecision::Allow;
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert!(!d.requires_approval());
    }

    #[test]
    fn mod_decision_deny() {
        let d = ModDecision::Deny {
            reason: "nope".into(),
        };
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert!(!d.requires_approval());
    }

    #[test]
    fn mod_decision_require_approval() {
        let d = ModDecision::RequireApproval {
            reason: "check".into(),
        };
        assert!(!d.is_allowed());
        assert!(!d.is_denied());
        assert!(d.requires_approval());
    }

    #[test]
    fn mod_decision_eq() {
        assert_eq!(ModDecision::Allow, ModDecision::Allow);
        assert_ne!(ModDecision::Allow, ModDecision::Deny { reason: "x".into() });
    }

    #[test]
    fn mod_decision_clone() {
        let d = ModDecision::RequireApproval { reason: "r".into() };
        #[allow(clippy::redundant_clone)]
        let d2 = d.clone();
        assert!(d2.requires_approval());
    }

    #[test]
    fn mod_decision_serde_roundtrip() {
        let d = ModDecision::Deny {
            reason: "policy".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: ModDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    // ── ModPolicy ───────────────────────────────────────────────────

    #[test]
    fn policy_full_allows_approve() {
        let p = ModPolicy::new_full();
        assert_eq!(p.check_action(&ModAction::Approve), ModDecision::Allow);
    }

    #[test]
    fn policy_full_requires_approval_for_remove() {
        let p = ModPolicy::new_full();
        assert!(p.check_action(&ModAction::Remove).requires_approval());
    }

    #[test]
    fn policy_full_requires_approval_for_spam() {
        let p = ModPolicy::new_full();
        assert!(p.check_action(&ModAction::Spam).requires_approval());
    }

    #[test]
    fn policy_full_requires_approval_for_lock() {
        let p = ModPolicy::new_full();
        assert!(p.check_action(&ModAction::Lock).requires_approval());
    }

    #[test]
    fn policy_full_requires_approval_for_ignore_reports() {
        let p = ModPolicy::new_full();
        assert!(
            p.check_action(&ModAction::IgnoreReports)
                .requires_approval()
        );
    }

    #[test]
    fn policy_full_allows_flair() {
        let p = ModPolicy::new_full();
        assert_eq!(p.check_action(&ModAction::SetFlair), ModDecision::Allow);
    }

    #[test]
    fn policy_full_allows_unlock() {
        let p = ModPolicy::new_full();
        assert_eq!(p.check_action(&ModAction::Unlock), ModDecision::Allow);
    }

    #[test]
    fn policy_full_allows_distinguish() {
        let p = ModPolicy::new_full();
        assert_eq!(p.check_action(&ModAction::Distinguish), ModDecision::Allow);
    }

    #[test]
    fn policy_full_allows_sticky() {
        let p = ModPolicy::new_full();
        assert_eq!(p.check_action(&ModAction::Sticky), ModDecision::Allow);
    }

    #[test]
    fn policy_full_allows_unsticky() {
        let p = ModPolicy::new_full();
        assert_eq!(p.check_action(&ModAction::Unsticky), ModDecision::Allow);
    }

    #[test]
    fn policy_full_allows_undistinguish() {
        let p = ModPolicy::new_full();
        assert_eq!(
            p.check_action(&ModAction::Undistinguish),
            ModDecision::Allow
        );
    }

    #[test]
    fn policy_full_allows_unignore_reports() {
        let p = ModPolicy::new_full();
        assert_eq!(
            p.check_action(&ModAction::UnignoreReports),
            ModDecision::Allow
        );
    }

    #[test]
    fn policy_readonly_denies_approve() {
        let p = ModPolicy::new_readonly();
        assert!(p.check_action(&ModAction::Approve).is_denied());
    }

    #[test]
    fn policy_readonly_denies_remove() {
        let p = ModPolicy::new_readonly();
        assert!(p.check_action(&ModAction::Remove).is_denied());
    }

    #[test]
    fn policy_readonly_denies_flair() {
        let p = ModPolicy::new_readonly();
        assert!(p.check_action(&ModAction::SetFlair).is_denied());
    }

    #[test]
    fn policy_readonly_denies_lock() {
        let p = ModPolicy::new_readonly();
        assert!(p.check_action(&ModAction::Lock).is_denied());
    }

    #[test]
    fn policy_readonly_denies_ignore_reports() {
        let p = ModPolicy::new_readonly();
        assert!(p.check_action(&ModAction::IgnoreReports).is_denied());
    }

    #[test]
    fn policy_readonly_denies_unlock() {
        let p = ModPolicy::new_readonly();
        assert!(p.check_action(&ModAction::Unlock).is_denied());
    }

    #[test]
    fn policy_full_no_approval_required_for_remove() {
        let mut p = ModPolicy::new_full();
        p.require_approval_for_remove = false;
        assert_eq!(p.check_action(&ModAction::Remove), ModDecision::Allow);
    }

    #[test]
    fn policy_full_no_approval_required_for_lock() {
        let mut p = ModPolicy::new_full();
        p.require_approval_for_remove = false;
        assert_eq!(p.check_action(&ModAction::Lock), ModDecision::Allow);
    }

    // ── ModPolicy: check_ban ────────────────────────────────────────

    #[test]
    fn policy_check_ban_allowed() {
        let mut p = ModPolicy::new_full();
        p.require_approval_for_ban = false;
        let r = valid_ban();
        assert_eq!(p.check_ban(&r), ModDecision::Allow);
    }

    #[test]
    fn policy_check_ban_requires_approval() {
        let p = ModPolicy::new_full();
        let r = valid_ban();
        assert!(p.check_ban(&r).requires_approval());
    }

    #[test]
    fn policy_check_ban_not_allowed() {
        let p = ModPolicy::new_readonly();
        let r = valid_ban();
        assert!(p.check_ban(&r).is_denied());
    }

    #[test]
    fn policy_check_ban_protected_user() {
        let mut p = ModPolicy::new_full();
        p.protected_users.insert("spammer".into());
        let r = valid_ban();
        let decision = p.check_ban(&r);
        assert!(decision.is_denied());
        if let ModDecision::Deny { reason } = decision {
            assert!(reason.contains("protected"));
        }
    }

    #[test]
    fn policy_check_ban_exceeds_max_duration() {
        let mut p = ModPolicy::new_full();
        p.max_ban_duration_days = Some(7);
        let r = valid_ban(); // 30 days
        assert!(p.check_ban(&r).is_denied());
    }

    #[test]
    fn policy_check_ban_within_max_duration() {
        let mut p = ModPolicy::new_full();
        p.max_ban_duration_days = Some(30);
        p.require_approval_for_ban = false;
        let r = valid_ban(); // 30 days
        assert_eq!(p.check_ban(&r), ModDecision::Allow);
    }

    #[test]
    fn policy_check_ban_permanent_with_max() {
        let mut p = ModPolicy::new_full();
        p.max_ban_duration_days = Some(30);
        let mut r = valid_ban();
        r.duration_days = None;
        let decision = p.check_ban(&r);
        assert!(decision.is_denied());
        if let ModDecision::Deny { reason } = decision {
            assert!(reason.contains("permanent"));
        }
    }

    #[test]
    fn policy_check_ban_permanent_no_max() {
        let mut p = ModPolicy::new_full();
        p.require_approval_for_ban = false;
        let mut r = valid_ban();
        r.duration_days = None;
        assert_eq!(p.check_ban(&r), ModDecision::Allow);
    }

    #[test]
    fn policy_clone() {
        let p = ModPolicy::new_full();
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert!(p2.allow_approve);
    }

    #[test]
    fn policy_debug() {
        let dbg = format!("{:?}", ModPolicy::new_full());
        assert!(dbg.contains("allow_approve"));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ModPolicy::new_full();
        p.protected_users.insert("admin".into());
        p.max_ban_duration_days = Some(90);
        let json = serde_json::to_string(&p).unwrap();
        let back: ModPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.protected_users.contains("admin"));
        assert_eq!(back.max_ban_duration_days, Some(90));
    }

    // ── ModValidator ────────────────────────────────────────────────

    #[test]
    fn validator_new_defaults() {
        let v = ModValidator::new();
        assert_eq!(v.max_ban_reason_length, 500);
        assert_eq!(v.max_note_length, 300);
        assert_eq!(v.max_flair_length, 64);
    }

    #[test]
    fn validator_default_trait() {
        let v = ModValidator::default();
        assert_eq!(v.max_ban_reason_length, 500);
    }

    #[test]
    fn validator_validate_ban_ok() {
        let v = ModValidator::new();
        assert!(v.validate_ban(&valid_ban()).is_ok());
    }

    #[test]
    fn validator_validate_ban_reason_too_long() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.reason = "x".repeat(501);
        assert!(matches!(
            v.validate_ban(&r).unwrap_err(),
            ModValidationError::ReasonTooLong {
                length: 501,
                max: 500
            }
        ));
    }

    #[test]
    fn validator_validate_ban_reason_at_limit() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.reason = "x".repeat(500);
        assert!(v.validate_ban(&r).is_ok());
    }

    #[test]
    fn validator_validate_ban_note_too_long() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.note = Some("x".repeat(301));
        assert!(matches!(
            v.validate_ban(&r).unwrap_err(),
            ModValidationError::NoteTooLong {
                length: 301,
                max: 300
            }
        ));
    }

    #[test]
    fn validator_validate_ban_note_at_limit() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.note = Some("x".repeat(300));
        assert!(v.validate_ban(&r).is_ok());
    }

    #[test]
    fn validator_validate_ban_no_note() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.note = None;
        assert!(v.validate_ban(&r).is_ok());
    }

    #[test]
    fn validator_validate_ban_propagates_base_error() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.username = String::new();
        assert_eq!(
            v.validate_ban(&r).unwrap_err(),
            ModValidationError::EmptyUsername
        );
    }

    #[test]
    fn validator_validate_flair_ok() {
        let v = ModValidator::new();
        assert!(v.validate_flair(&valid_flair()).is_ok());
    }

    #[test]
    fn validator_validate_flair_empty_thing_id() {
        let v = ModValidator::new();
        let mut r = valid_flair();
        r.thing_id = String::new();
        assert!(matches!(
            v.validate_flair(&r).unwrap_err(),
            ModValidationError::InvalidThingId { .. }
        ));
    }

    #[test]
    fn validator_validate_flair_empty_subreddit() {
        let v = ModValidator::new();
        let mut r = valid_flair();
        r.subreddit = String::new();
        assert_eq!(
            v.validate_flair(&r).unwrap_err(),
            ModValidationError::EmptySubreddit
        );
    }

    #[test]
    fn validator_validate_flair_text_too_long() {
        let v = ModValidator::new();
        let mut r = valid_flair();
        r.flair_text = Some("x".repeat(65));
        assert!(matches!(
            v.validate_flair(&r).unwrap_err(),
            ModValidationError::FlairTooLong {
                length: 65,
                max: 64
            }
        ));
    }

    #[test]
    fn validator_validate_flair_text_at_limit() {
        let v = ModValidator::new();
        let mut r = valid_flair();
        r.flair_text = Some("x".repeat(64));
        assert!(v.validate_flair(&r).is_ok());
    }

    #[test]
    fn validator_validate_flair_no_text() {
        let v = ModValidator::new();
        let mut r = valid_flair();
        r.flair_text = None;
        assert!(v.validate_flair(&r).is_ok());
    }

    #[test]
    fn validator_custom_limits() {
        let v = ModValidator {
            max_ban_reason_length: 10,
            max_note_length: 5,
            max_flair_length: 3,
        };
        let mut r = valid_ban();
        r.reason = "x".repeat(11);
        assert!(matches!(
            v.validate_ban(&r).unwrap_err(),
            ModValidationError::ReasonTooLong {
                length: 11,
                max: 10
            }
        ));
    }

    #[test]
    fn validator_custom_note_limit() {
        let v = ModValidator {
            max_ban_reason_length: 500,
            max_note_length: 5,
            max_flair_length: 64,
        };
        let mut r = valid_ban();
        r.note = Some("x".repeat(6));
        assert!(matches!(
            v.validate_ban(&r).unwrap_err(),
            ModValidationError::NoteTooLong { length: 6, max: 5 }
        ));
    }

    #[test]
    fn validator_custom_flair_limit() {
        let v = ModValidator {
            max_ban_reason_length: 500,
            max_note_length: 300,
            max_flair_length: 3,
        };
        let mut r = valid_flair();
        r.flair_text = Some("abcd".into());
        assert!(matches!(
            v.validate_flair(&r).unwrap_err(),
            ModValidationError::FlairTooLong { length: 4, max: 3 }
        ));
    }

    #[test]
    fn validator_clone() {
        let v = ModValidator::new();
        #[allow(clippy::redundant_clone)]
        let v2 = v.clone();
        assert_eq!(v2.max_ban_reason_length, 500);
    }

    #[test]
    fn validator_serde_roundtrip() {
        let v = ModValidator::new();
        let json = serde_json::to_string(&v).unwrap();
        let back: ModValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_flair_length, 64);
    }

    // ── ModValidationError ──────────────────────────────────────────

    #[test]
    fn validation_error_display_empty_username() {
        assert_eq!(
            ModValidationError::EmptyUsername.to_string(),
            "username must not be empty"
        );
    }

    #[test]
    fn validation_error_display_empty_subreddit() {
        assert_eq!(
            ModValidationError::EmptySubreddit.to_string(),
            "subreddit must not be empty"
        );
    }

    #[test]
    fn validation_error_display_empty_reason() {
        assert_eq!(
            ModValidationError::EmptyReason.to_string(),
            "reason must not be empty"
        );
    }

    #[test]
    fn validation_error_display_reason_too_long() {
        let e = ModValidationError::ReasonTooLong {
            length: 600,
            max: 500,
        };
        assert_eq!(e.to_string(), "reason too long (600 chars, max 500)");
    }

    #[test]
    fn validation_error_display_note_too_long() {
        let e = ModValidationError::NoteTooLong {
            length: 400,
            max: 300,
        };
        assert_eq!(e.to_string(), "note too long (400 chars, max 300)");
    }

    #[test]
    fn validation_error_display_flair_too_long() {
        let e = ModValidationError::FlairTooLong {
            length: 100,
            max: 64,
        };
        assert_eq!(e.to_string(), "flair text too long (100 chars, max 64)");
    }

    #[test]
    fn validation_error_display_invalid_duration() {
        let e = ModValidationError::InvalidDuration {
            days: 0,
            reason: "must be > 0".into(),
        };
        assert_eq!(e.to_string(), "invalid ban duration (0 days): must be > 0");
    }

    #[test]
    fn validation_error_display_protected_user() {
        let e = ModValidationError::ProtectedUser {
            username: "admin".into(),
        };
        assert_eq!(e.to_string(), "user 'admin' is protected");
    }

    #[test]
    fn validation_error_display_invalid_thing_id() {
        let e = ModValidationError::InvalidThingId {
            id: "bad".into(),
            reason: "wrong prefix".into(),
        };
        assert_eq!(e.to_string(), "invalid thing ID 'bad': wrong prefix");
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            ModValidationError::EmptyUsername,
            ModValidationError::EmptyUsername
        );
        assert_ne!(
            ModValidationError::EmptyUsername,
            ModValidationError::EmptyReason
        );
    }

    #[test]
    fn validation_error_clone() {
        let e = ModValidationError::ReasonTooLong { length: 10, max: 5 };
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e, e2);
    }

    #[test]
    fn validation_error_debug() {
        let dbg = format!("{:?}", ModValidationError::EmptyUsername);
        assert!(dbg.contains("EmptyUsername"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let e = ModValidationError::ProtectedUser {
            username: "u".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ModValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn validation_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(ModValidationError::EmptyUsername);
        assert!(e.to_string().contains("username"));
    }

    // ── ModAuditEvent ───────────────────────────────────────────────

    #[test]
    fn audit_event_new() {
        let e = ModAuditEvent::new(
            1000,
            "approve",
            "t3_abc",
            "rust",
            Some("mod_user".into()),
            "approved post",
            true,
        );
        assert_eq!(e.timestamp, 1000);
        assert_eq!(e.action, "approve");
        assert_eq!(e.target_id, "t3_abc");
        assert_eq!(e.subreddit, "rust");
        assert_eq!(e.moderator, Some("mod_user".into()));
        assert!(e.was_allowed);
    }

    #[test]
    fn audit_event_denied() {
        let e = ModAuditEvent::denied(2000, &ModAction::Remove, "t3_xyz", "test", "policy");
        assert_eq!(e.timestamp, 2000);
        assert_eq!(e.action, "remove");
        assert!(!e.was_allowed);
        assert!(e.details.contains("Denied"));
        assert!(e.details.contains("policy"));
    }

    #[test]
    fn audit_event_allowed() {
        let e = ModAuditEvent::allowed(
            3000,
            &ModAction::Lock,
            "t3_lock",
            "sub",
            Some("moderator".into()),
        );
        assert_eq!(e.timestamp, 3000);
        assert_eq!(e.action, "lock");
        assert!(e.was_allowed);
        assert_eq!(e.moderator, Some("moderator".into()));
    }

    #[test]
    fn audit_event_allowed_no_moderator() {
        let e = ModAuditEvent::allowed(4000, &ModAction::Approve, "t1_c", "sub", None);
        assert!(e.moderator.is_none());
        assert!(e.was_allowed);
    }

    #[test]
    fn audit_event_clone() {
        let e = ModAuditEvent::new(100, "test", "t3_x", "s", None, "d", true);
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.timestamp, 100);
    }

    #[test]
    fn audit_event_debug() {
        let e = ModAuditEvent::new(0, "remove", "t3_d", "r", None, "debug", false);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("remove"));
        assert!(dbg.contains("t3_d"));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let e = ModAuditEvent::new(
            5000,
            "ban",
            "t2_user",
            "sub",
            Some("admin".into()),
            "banned user",
            true,
        );
        let json = serde_json::to_string(&e).unwrap();
        let back: ModAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp, 5000);
        assert_eq!(back.action, "ban");
        assert_eq!(back.moderator, Some("admin".into()));
    }

    #[test]
    fn audit_event_denied_all_actions() {
        for action in &[
            ModAction::Approve,
            ModAction::Remove,
            ModAction::Spam,
            ModAction::Lock,
        ] {
            let e = ModAuditEvent::denied(0, action, "t3_x", "s", "test");
            assert!(!e.was_allowed);
            assert_eq!(e.action, action.as_str());
        }
    }

    // ── Integration / cross-type tests ──────────────────────────────

    #[test]
    fn full_policy_ban_flow() {
        let policy = ModPolicy::new_full();
        let ban = valid_ban();
        let validator = ModValidator::new();

        // Validate the ban request
        assert!(validator.validate_ban(&ban).is_ok());

        // Check policy
        let decision = policy.check_ban(&ban);
        assert!(decision.requires_approval());

        // Create audit event
        let audit = ModAuditEvent::denied(
            1000,
            &ModAction::Remove, // using Remove as proxy for ban action
            &ban.username,
            &ban.subreddit,
            "requires approval",
        );
        assert!(!audit.was_allowed);
    }

    #[test]
    fn full_remove_flow() {
        let mut policy = ModPolicy::new_full();
        policy.require_approval_for_remove = false;

        let target = ModTarget::new("t3_abc", "rust", ContentType::Post);
        let decision = policy.check_action(&ModAction::Remove);
        assert_eq!(decision, ModDecision::Allow);

        let result = ModActionResult::success(ModAction::Remove, &target.thing_id, 2000);
        assert!(result.success);

        let audit = ModAuditEvent::allowed(
            2000,
            &ModAction::Remove,
            &target.thing_id,
            &target.subreddit,
            Some("bot".into()),
        );
        assert!(audit.was_allowed);
    }

    #[test]
    fn readonly_policy_denies_everything() {
        let p = ModPolicy::new_readonly();
        let all_actions = [
            ModAction::Approve,
            ModAction::Remove,
            ModAction::Spam,
            ModAction::Lock,
            ModAction::Unlock,
            ModAction::Distinguish,
            ModAction::Undistinguish,
            ModAction::Sticky,
            ModAction::Unsticky,
            ModAction::SetFlair,
            ModAction::IgnoreReports,
            ModAction::UnignoreReports,
        ];
        for action in &all_actions {
            assert!(
                p.check_action(action).is_denied(),
                "readonly should deny {action:?}"
            );
        }
    }

    #[test]
    fn protected_user_ban_denied_reason() {
        let mut p = ModPolicy::new_full();
        p.protected_users.insert("admin_bot".into());

        let mut r = valid_ban();
        r.username = "admin_bot".into();

        match p.check_ban(&r) {
            ModDecision::Deny { reason } => {
                assert!(reason.contains("admin_bot"));
                assert!(reason.contains("protected"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn ban_duration_exactly_at_max() {
        let mut p = ModPolicy::new_full();
        p.max_ban_duration_days = Some(30);
        p.require_approval_for_ban = false;

        let mut r = valid_ban();
        r.duration_days = Some(30);
        assert_eq!(p.check_ban(&r), ModDecision::Allow);
    }

    #[test]
    fn ban_duration_one_over_max() {
        let mut p = ModPolicy::new_full();
        p.max_ban_duration_days = Some(30);

        let mut r = valid_ban();
        r.duration_days = Some(31);
        assert!(p.check_ban(&r).is_denied());
    }

    #[test]
    fn flair_request_only_css_class() {
        let r = FlairRequest {
            thing_id: "t3_abc".into(),
            subreddit: "test".into(),
            flair_text: None,
            flair_css_class: Some("css-class".into()),
            flair_template_id: None,
        };
        assert!(r.has_any_flair());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn content_type_all_variants_have_prefix() {
        let types = [ContentType::Post, ContentType::Comment, ContentType::User];
        for ct in &types {
            let prefix = ct.thing_prefix();
            assert!(prefix.starts_with('t'));
            assert!(prefix.ends_with('_'));
        }
    }

    #[test]
    fn mod_target_wrong_prefix_comment_as_post() {
        let t = ModTarget::new("t3_abc", "test", ContentType::Comment);
        assert!(!t.has_valid_prefix());
    }

    #[test]
    fn mod_target_wrong_prefix_user_as_comment() {
        let t = ModTarget::new("t2_abc", "test", ContentType::Comment);
        assert!(!t.has_valid_prefix());
    }

    #[test]
    fn validator_ban_empty_username_before_length_check() {
        let v = ModValidator::new();
        let mut r = valid_ban();
        r.username = String::new();
        r.reason = "x".repeat(600);
        // Should fail on username first, not reason length
        assert_eq!(
            v.validate_ban(&r).unwrap_err(),
            ModValidationError::EmptyUsername
        );
    }
}
