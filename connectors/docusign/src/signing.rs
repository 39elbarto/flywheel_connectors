//! `DocuSign` Send-for-Signature operations.
//!
//! Provides types and validation for transitioning envelopes from draft to sent,
//! resending notifications, voiding/cancelling envelopes, and correcting envelopes.
//! All operations produce a full audit trail.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SigningAction
// ---------------------------------------------------------------------------

/// An action that can be performed on a `DocuSign` envelope during the signing
/// lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAction {
    /// Transition an envelope from draft to sent.
    Send,
    /// Resend signing notifications to recipients.
    Resend,
    /// Void (cancel) an envelope permanently.
    Void {
        /// The reason for voiding the envelope.
        reason: String,
    },
    /// Correct an in-flight envelope (e.g. fix recipient info).
    Correct,
}

impl SigningAction {
    /// Returns a human-readable string representation of the action.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Send => "send",
            Self::Resend => "resend",
            Self::Void { .. } => "void",
            Self::Correct => "correct",
        }
    }

    /// Returns `true` if the action has destructive side effects that
    /// cannot be undone.
    #[must_use]
    pub const fn is_destructive(&self) -> bool {
        matches!(self, Self::Void { .. })
    }

    /// Returns `true` if the action should require explicit approval
    /// before being executed.
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(self, Self::Send | Self::Void { .. })
    }
}

impl std::fmt::Display for SigningAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send => write!(f, "send"),
            Self::Resend => write!(f, "resend"),
            Self::Void { reason } => write!(f, "void({reason})"),
            Self::Correct => write!(f, "correct"),
        }
    }
}

// ---------------------------------------------------------------------------
// NotificationConfig
// ---------------------------------------------------------------------------

/// Configuration for notification overrides when sending or resending
/// a `DocuSign` envelope.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationConfig {
    /// Override the email subject line.
    pub subject_override: Option<String>,
    /// Override the email body message.
    pub message_override: Option<String>,
    /// Whether to enable reminders.
    pub reminder_enabled: bool,
    /// Number of days after sending before the first reminder.
    pub reminder_delay_days: Option<u32>,
    /// Number of days between subsequent reminders.
    pub reminder_frequency_days: Option<u32>,
    /// Number of days until the envelope expires.
    pub expiration_days: Option<u32>,
}

// ---------------------------------------------------------------------------
// SendRequest
// ---------------------------------------------------------------------------

/// Request to send (transition from draft to sent) a `DocuSign` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRequest {
    /// The `DocuSign` envelope ID to send.
    pub envelope_id: String,
    /// Optional notification configuration overrides.
    pub notification_override: Option<NotificationConfig>,
}

impl SendRequest {
    /// Validates the send request.
    ///
    /// # Errors
    ///
    /// Returns `SigningValidationError::EmptyEnvelopeId` if the envelope ID is
    /// empty or whitespace-only.
    pub fn validate(&self) -> Result<(), SigningValidationError> {
        if self.envelope_id.trim().is_empty() {
            return Err(SigningValidationError::EmptyEnvelopeId);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VoidRequest
// ---------------------------------------------------------------------------

/// Request to void (cancel) a `DocuSign` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoidRequest {
    /// The envelope to void.
    pub envelope_id: String,
    /// The reason for voiding.
    pub reason: String,
}

impl VoidRequest {
    /// Validates the void request.
    ///
    /// # Errors
    ///
    /// Returns a `SigningValidationError` if the envelope ID is empty,
    /// the reason is empty, or the reason exceeds 200 characters.
    pub fn validate(&self) -> Result<(), SigningValidationError> {
        if self.envelope_id.trim().is_empty() {
            return Err(SigningValidationError::EmptyEnvelopeId);
        }
        if self.reason.trim().is_empty() {
            return Err(SigningValidationError::EmptyReason);
        }
        if self.reason.len() > 200 {
            return Err(SigningValidationError::ReasonTooLong {
                length: self.reason.len(),
                max: 200,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ResendRequest
// ---------------------------------------------------------------------------

/// Request to resend signing notifications for a `DocuSign` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendRequest {
    /// The envelope whose notifications should be resent.
    pub envelope_id: String,
    /// Optionally limit the resend to specific recipient IDs.
    pub recipient_ids: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// SigningResult
// ---------------------------------------------------------------------------

/// The result of a signing lifecycle operation on a `DocuSign` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    /// The envelope that was acted upon.
    pub envelope_id: String,
    /// The action that was performed.
    pub action: SigningAction,
    /// Whether the operation succeeded.
    pub success: bool,
    /// The new envelope status after the operation (e.g. "sent", "voided").
    pub new_status: Option<String>,
    /// An error message if the operation failed.
    pub error_message: Option<String>,
    /// ISO-8601 timestamp of when the operation completed.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// SigningPolicy
// ---------------------------------------------------------------------------

/// Policy that governs which signing actions are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SigningPolicy {
    /// Whether the `Send` action is allowed.
    pub allow_send: bool,
    /// Whether the `Resend` action is allowed.
    pub allow_resend: bool,
    /// Whether the `Void` action is allowed.
    pub allow_void: bool,
    /// Whether the `Send` action requires approval.
    pub require_approval_for_send: bool,
    /// Whether the `Void` action requires approval.
    pub require_approval_for_void: bool,
    /// Maximum number of send operations per hour (rate limit).
    pub max_sends_per_hour: Option<u32>,
    /// Envelope IDs that are blocked from any action.
    pub blocked_envelope_ids: HashSet<String>,
}

impl SigningPolicy {
    /// Creates a permissive policy that allows all actions without approval.
    #[must_use]
    pub fn new_permissive() -> Self {
        Self {
            allow_send: true,
            allow_resend: true,
            allow_void: true,
            require_approval_for_send: false,
            require_approval_for_void: false,
            max_sends_per_hour: None,
            blocked_envelope_ids: HashSet::new(),
        }
    }

    /// Creates a read-only policy that denies all actions.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_send: false,
            allow_resend: false,
            allow_void: false,
            require_approval_for_send: false,
            require_approval_for_void: false,
            max_sends_per_hour: None,
            blocked_envelope_ids: HashSet::new(),
        }
    }

    /// Checks whether the given action is allowed by this policy for the
    /// specified envelope.
    #[must_use]
    pub fn check_action(&self, action: &SigningAction, envelope_id: &str) -> SigningDecision {
        if self.blocked_envelope_ids.contains(envelope_id) {
            return SigningDecision::Deny {
                reason: format!("Envelope {envelope_id} is blocked by policy"),
            };
        }

        match action {
            SigningAction::Send => {
                if !self.allow_send {
                    SigningDecision::Deny {
                        reason: "Send action is not permitted by policy".into(),
                    }
                } else if self.require_approval_for_send {
                    SigningDecision::RequireApproval {
                        reason: "Send action requires approval".into(),
                    }
                } else {
                    SigningDecision::Allow
                }
            }
            SigningAction::Resend => {
                if self.allow_resend {
                    SigningDecision::Allow
                } else {
                    SigningDecision::Deny {
                        reason: "Resend action is not permitted by policy".into(),
                    }
                }
            }
            SigningAction::Void { .. } => {
                if !self.allow_void {
                    SigningDecision::Deny {
                        reason: "Void action is not permitted by policy".into(),
                    }
                } else if self.require_approval_for_void {
                    SigningDecision::RequireApproval {
                        reason: "Void action requires approval".into(),
                    }
                } else {
                    SigningDecision::Allow
                }
            }
            SigningAction::Correct => {
                // Correct follows the same permission as Send since it modifies
                // envelope state.
                if self.allow_send {
                    SigningDecision::Allow
                } else {
                    SigningDecision::Deny {
                        reason: "Correct action is not permitted by policy".into(),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SigningDecision
// ---------------------------------------------------------------------------

/// The outcome of a policy check for a signing action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningDecision {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny {
        /// Reason the action was denied.
        reason: String,
    },
    /// The action requires explicit approval before proceeding.
    RequireApproval {
        /// Reason approval is required.
        reason: String,
    },
}

impl SigningDecision {
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

impl std::fmt::Display for SigningDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allowed"),
            Self::Deny { reason } => write!(f, "denied: {reason}"),
            Self::RequireApproval { reason } => write!(f, "requires approval: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SigningValidator
// ---------------------------------------------------------------------------

/// Validates signing-related requests against configurable constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningValidator {
    /// Maximum length for a void reason.
    pub max_reason_length: usize,
    /// Maximum length for a notification subject override.
    pub max_subject_length: usize,
    /// Maximum number of expiration days.
    pub max_expiration_days: u32,
}

impl Default for SigningValidator {
    fn default() -> Self {
        Self {
            max_reason_length: 200,
            max_subject_length: 100,
            max_expiration_days: 120,
        }
    }
}

impl SigningValidator {
    /// Validates a send request.
    ///
    /// # Errors
    ///
    /// Returns a `SigningValidationError` if the request is invalid.
    pub fn validate_send(&self, req: &SendRequest) -> Result<(), SigningValidationError> {
        req.validate()?;
        if let Some(ref notification) = req.notification_override {
            self.validate_notification(notification)?;
        }
        Ok(())
    }

    /// Validates a void request.
    ///
    /// # Errors
    ///
    /// Returns a `SigningValidationError` if the request is invalid.
    pub fn validate_void(&self, req: &VoidRequest) -> Result<(), SigningValidationError> {
        if req.envelope_id.trim().is_empty() {
            return Err(SigningValidationError::EmptyEnvelopeId);
        }
        if req.reason.trim().is_empty() {
            return Err(SigningValidationError::EmptyReason);
        }
        if req.reason.len() > self.max_reason_length {
            return Err(SigningValidationError::ReasonTooLong {
                length: req.reason.len(),
                max: self.max_reason_length,
            });
        }
        Ok(())
    }

    /// Validates a notification configuration.
    ///
    /// # Errors
    ///
    /// Returns a `SigningValidationError` if the configuration is invalid.
    pub fn validate_notification(
        &self,
        config: &NotificationConfig,
    ) -> Result<(), SigningValidationError> {
        if let Some(ref subject) = config.subject_override {
            if subject.len() > self.max_subject_length {
                return Err(SigningValidationError::SubjectTooLong {
                    length: subject.len(),
                    max: self.max_subject_length,
                });
            }
        }
        if let Some(days) = config.expiration_days {
            if days == 0 || days > self.max_expiration_days {
                return Err(SigningValidationError::InvalidExpirationDays {
                    days,
                    max: self.max_expiration_days,
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SigningValidationError
// ---------------------------------------------------------------------------

/// Validation errors for signing requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningValidationError {
    /// The envelope ID was empty or whitespace-only.
    EmptyEnvelopeId,
    /// The void reason was empty or whitespace-only.
    EmptyReason,
    /// The void reason exceeded the maximum length.
    ReasonTooLong {
        /// Actual length.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// The notification subject override exceeded the maximum length.
    SubjectTooLong {
        /// Actual length.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// The expiration days value is invalid (zero or exceeds max).
    InvalidExpirationDays {
        /// The invalid days value.
        days: u32,
        /// Maximum allowed days.
        max: u32,
    },
    /// The envelope is on the policy block list.
    BlockedEnvelope {
        /// The blocked envelope ID.
        envelope_id: String,
    },
}

impl std::fmt::Display for SigningValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEnvelopeId => write!(f, "envelope ID must not be empty"),
            Self::EmptyReason => write!(f, "void reason must not be empty"),
            Self::ReasonTooLong { length, max } => {
                write!(f, "reason too long: {length} chars (max {max})")
            }
            Self::SubjectTooLong { length, max } => {
                write!(f, "subject too long: {length} chars (max {max})")
            }
            Self::InvalidExpirationDays { days, max } => {
                write!(f, "invalid expiration days: {days} (must be 1..={max})")
            }
            Self::BlockedEnvelope { envelope_id } => {
                write!(f, "envelope {envelope_id} is blocked by policy")
            }
        }
    }
}

impl std::error::Error for SigningValidationError {}

// ---------------------------------------------------------------------------
// SigningAuditEvent
// ---------------------------------------------------------------------------

/// An audit event recording a signing action and its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningAuditEvent {
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,
    /// The action that was attempted.
    pub action: SigningAction,
    /// The envelope the action targeted.
    pub envelope_id: String,
    /// Whether the action was allowed and succeeded.
    pub was_allowed: bool,
    /// Additional details about the event.
    pub details: String,
}

impl SigningAuditEvent {
    /// Creates a new audit event.
    #[must_use]
    pub fn new(
        timestamp: impl Into<String>,
        action: SigningAction,
        envelope_id: impl Into<String>,
        was_allowed: bool,
        details: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: timestamp.into(),
            action,
            envelope_id: envelope_id.into(),
            was_allowed,
            details: details.into(),
        }
    }
}

impl std::fmt::Display for SigningAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.was_allowed {
            "ALLOWED"
        } else {
            "DENIED"
        };
        write!(
            f,
            "[{}] {} {} on envelope {}: {}",
            self.timestamp,
            status,
            self.action.as_str(),
            self.envelope_id,
            self.details,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===== SigningAction tests =====

    #[test]
    fn action_send_as_str() {
        assert_eq!(SigningAction::Send.as_str(), "send");
    }

    #[test]
    fn action_resend_as_str() {
        assert_eq!(SigningAction::Resend.as_str(), "resend");
    }

    #[test]
    fn action_void_as_str() {
        let action = SigningAction::Void {
            reason: "test".into(),
        };
        assert_eq!(action.as_str(), "void");
    }

    #[test]
    fn action_correct_as_str() {
        assert_eq!(SigningAction::Correct.as_str(), "correct");
    }

    #[test]
    fn action_send_not_destructive() {
        assert!(!SigningAction::Send.is_destructive());
    }

    #[test]
    fn action_resend_not_destructive() {
        assert!(!SigningAction::Resend.is_destructive());
    }

    #[test]
    fn action_void_is_destructive() {
        let action = SigningAction::Void {
            reason: "cancelled".into(),
        };
        assert!(action.is_destructive());
    }

    #[test]
    fn action_correct_not_destructive() {
        assert!(!SigningAction::Correct.is_destructive());
    }

    #[test]
    fn action_send_requires_approval() {
        assert!(SigningAction::Send.requires_approval());
    }

    #[test]
    fn action_resend_no_approval() {
        assert!(!SigningAction::Resend.requires_approval());
    }

    #[test]
    fn action_void_requires_approval() {
        let action = SigningAction::Void {
            reason: "test".into(),
        };
        assert!(action.requires_approval());
    }

    #[test]
    fn action_correct_no_approval() {
        assert!(!SigningAction::Correct.requires_approval());
    }

    #[test]
    fn action_display_send() {
        assert_eq!(SigningAction::Send.to_string(), "send");
    }

    #[test]
    fn action_display_resend() {
        assert_eq!(SigningAction::Resend.to_string(), "resend");
    }

    #[test]
    fn action_display_void() {
        let action = SigningAction::Void {
            reason: "no longer needed".into(),
        };
        assert_eq!(action.to_string(), "void(no longer needed)");
    }

    #[test]
    fn action_display_correct() {
        assert_eq!(SigningAction::Correct.to_string(), "correct");
    }

    #[test]
    fn action_send_equality() {
        assert_eq!(SigningAction::Send, SigningAction::Send);
    }

    #[test]
    fn action_resend_equality() {
        assert_eq!(SigningAction::Resend, SigningAction::Resend);
    }

    #[test]
    fn action_void_equality() {
        let a = SigningAction::Void {
            reason: "same".into(),
        };
        let b = SigningAction::Void {
            reason: "same".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn action_void_inequality_different_reason() {
        let a = SigningAction::Void { reason: "a".into() };
        let b = SigningAction::Void { reason: "b".into() };
        assert_ne!(a, b);
    }

    #[test]
    fn action_send_ne_resend() {
        assert_ne!(SigningAction::Send, SigningAction::Resend);
    }

    #[test]
    fn action_clone() {
        let action = SigningAction::Void {
            reason: "cloned".into(),
        };
        let cloned = action.clone();
        drop(action);
        assert_eq!(cloned.as_str(), "void");
    }

    #[test]
    fn action_debug() {
        let dbg = format!("{:?}", SigningAction::Send);
        assert!(dbg.contains("Send"));
    }

    #[test]
    fn action_serialize_send() {
        let json = serde_json::to_string(&SigningAction::Send).unwrap();
        assert!(json.contains("Send"));
    }

    #[test]
    fn action_serialize_void() {
        let action = SigningAction::Void {
            reason: "expired".into(),
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("expired"));
    }

    #[test]
    fn action_roundtrip_send() {
        let json = serde_json::to_string(&SigningAction::Send).unwrap();
        let back: SigningAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SigningAction::Send);
    }

    #[test]
    fn action_roundtrip_resend() {
        let json = serde_json::to_string(&SigningAction::Resend).unwrap();
        let back: SigningAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SigningAction::Resend);
    }

    #[test]
    fn action_roundtrip_void() {
        let action = SigningAction::Void {
            reason: "roundtrip".into(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: SigningAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);
    }

    #[test]
    fn action_roundtrip_correct() {
        let json = serde_json::to_string(&SigningAction::Correct).unwrap();
        let back: SigningAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SigningAction::Correct);
    }

    // ===== SendRequest tests =====

    #[test]
    fn send_request_validate_ok() {
        let req = SendRequest {
            envelope_id: "env-123".into(),
            notification_override: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn send_request_validate_empty_id() {
        let req = SendRequest {
            envelope_id: String::new(),
            notification_override: None,
        };
        assert_eq!(
            req.validate().unwrap_err(),
            SigningValidationError::EmptyEnvelopeId
        );
    }

    #[test]
    fn send_request_validate_whitespace_id() {
        let req = SendRequest {
            envelope_id: "   ".into(),
            notification_override: None,
        };
        assert_eq!(
            req.validate().unwrap_err(),
            SigningValidationError::EmptyEnvelopeId
        );
    }

    #[test]
    fn send_request_with_notification() {
        let req = SendRequest {
            envelope_id: "env-456".into(),
            notification_override: Some(NotificationConfig {
                subject_override: Some("Please sign".into()),
                ..NotificationConfig::default()
            }),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn send_request_clone() {
        let req = SendRequest {
            envelope_id: "env-c".into(),
            notification_override: None,
        };
        let cloned = req.clone();
        drop(req);
        assert_eq!(cloned.envelope_id, "env-c");
    }

    #[test]
    fn send_request_debug() {
        let req = SendRequest {
            envelope_id: "env-d".into(),
            notification_override: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("SendRequest"));
    }

    #[test]
    fn send_request_serialize_roundtrip() {
        let req = SendRequest {
            envelope_id: "env-s".into(),
            notification_override: Some(NotificationConfig::default()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SendRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-s");
    }

    // ===== VoidRequest tests =====

    #[test]
    fn void_request_validate_ok() {
        let req = VoidRequest {
            envelope_id: "env-789".into(),
            reason: "No longer needed".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn void_request_validate_empty_id() {
        let req = VoidRequest {
            envelope_id: String::new(),
            reason: "valid reason".into(),
        };
        assert_eq!(
            req.validate().unwrap_err(),
            SigningValidationError::EmptyEnvelopeId
        );
    }

    #[test]
    fn void_request_validate_whitespace_id() {
        let req = VoidRequest {
            envelope_id: "  \t  ".into(),
            reason: "valid reason".into(),
        };
        assert_eq!(
            req.validate().unwrap_err(),
            SigningValidationError::EmptyEnvelopeId
        );
    }

    #[test]
    fn void_request_validate_empty_reason() {
        let req = VoidRequest {
            envelope_id: "env-001".into(),
            reason: String::new(),
        };
        assert_eq!(
            req.validate().unwrap_err(),
            SigningValidationError::EmptyReason
        );
    }

    #[test]
    fn void_request_validate_whitespace_reason() {
        let req = VoidRequest {
            envelope_id: "env-001".into(),
            reason: "   ".into(),
        };
        assert_eq!(
            req.validate().unwrap_err(),
            SigningValidationError::EmptyReason
        );
    }

    #[test]
    fn void_request_validate_reason_too_long() {
        let req = VoidRequest {
            envelope_id: "env-001".into(),
            reason: "x".repeat(201),
        };
        let err = req.validate().unwrap_err();
        assert_eq!(
            err,
            SigningValidationError::ReasonTooLong {
                length: 201,
                max: 200
            }
        );
    }

    #[test]
    fn void_request_validate_reason_exactly_200() {
        let req = VoidRequest {
            envelope_id: "env-001".into(),
            reason: "x".repeat(200),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn void_request_clone() {
        let req = VoidRequest {
            envelope_id: "env-v".into(),
            reason: "test".into(),
        };
        let cloned = req.clone();
        drop(req);
        assert_eq!(cloned.reason, "test");
    }

    #[test]
    fn void_request_debug() {
        let req = VoidRequest {
            envelope_id: "env-v".into(),
            reason: "debug".into(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("VoidRequest"));
    }

    #[test]
    fn void_request_serialize_roundtrip() {
        let req = VoidRequest {
            envelope_id: "env-sr".into(),
            reason: "roundtrip".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: VoidRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-sr");
        assert_eq!(back.reason, "roundtrip");
    }

    // ===== ResendRequest tests =====

    #[test]
    fn resend_request_no_recipients() {
        let req = ResendRequest {
            envelope_id: "env-100".into(),
            recipient_ids: None,
        };
        assert_eq!(req.envelope_id, "env-100");
        assert!(req.recipient_ids.is_none());
    }

    #[test]
    fn resend_request_with_recipients() {
        let req = ResendRequest {
            envelope_id: "env-101".into(),
            recipient_ids: Some(vec!["r1".into(), "r2".into()]),
        };
        assert_eq!(req.recipient_ids.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn resend_request_clone() {
        let req = ResendRequest {
            envelope_id: "env-r".into(),
            recipient_ids: Some(vec!["r1".into()]),
        };
        let cloned = req.clone();
        drop(req);
        assert_eq!(cloned.recipient_ids.unwrap().len(), 1);
    }

    #[test]
    fn resend_request_debug() {
        let req = ResendRequest {
            envelope_id: "env-r".into(),
            recipient_ids: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("ResendRequest"));
    }

    #[test]
    fn resend_request_serialize_roundtrip() {
        let req = ResendRequest {
            envelope_id: "env-rr".into(),
            recipient_ids: Some(vec!["a".into(), "b".into()]),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ResendRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-rr");
        assert_eq!(back.recipient_ids.unwrap().len(), 2);
    }

    // ===== NotificationConfig tests =====

    #[test]
    fn notification_config_default() {
        let config = NotificationConfig::default();
        assert!(config.subject_override.is_none());
        assert!(config.message_override.is_none());
        assert!(!config.reminder_enabled);
        assert!(config.reminder_delay_days.is_none());
        assert!(config.reminder_frequency_days.is_none());
        assert!(config.expiration_days.is_none());
    }

    #[test]
    fn notification_config_with_all_fields() {
        let config = NotificationConfig {
            subject_override: Some("Custom subject".into()),
            message_override: Some("Custom message".into()),
            reminder_enabled: true,
            reminder_delay_days: Some(3),
            reminder_frequency_days: Some(2),
            expiration_days: Some(30),
        };
        assert_eq!(config.subject_override, Some("Custom subject".into()));
        assert!(config.reminder_enabled);
        assert_eq!(config.expiration_days, Some(30));
    }

    #[test]
    fn notification_config_clone() {
        let config = NotificationConfig {
            subject_override: Some("test".into()),
            ..NotificationConfig::default()
        };
        let cloned = config.clone();
        drop(config);
        assert_eq!(cloned.subject_override, Some("test".into()));
    }

    #[test]
    fn notification_config_equality() {
        let a = NotificationConfig::default();
        let b = NotificationConfig::default();
        assert_eq!(a, b);
    }

    #[test]
    fn notification_config_inequality() {
        let a = NotificationConfig::default();
        let b = NotificationConfig {
            reminder_enabled: true,
            ..NotificationConfig::default()
        };
        assert_ne!(a, b);
    }

    #[test]
    fn notification_config_serialize_roundtrip() {
        let config = NotificationConfig {
            subject_override: Some("Sign now".into()),
            message_override: None,
            reminder_enabled: true,
            reminder_delay_days: Some(5),
            reminder_frequency_days: Some(3),
            expiration_days: Some(60),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: NotificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    // ===== SigningResult tests =====

    #[test]
    fn signing_result_success() {
        let result = SigningResult {
            envelope_id: "env-200".into(),
            action: SigningAction::Send,
            success: true,
            new_status: Some("sent".into()),
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(result.success);
        assert_eq!(result.new_status, Some("sent".into()));
    }

    #[test]
    fn signing_result_failure() {
        let result = SigningResult {
            envelope_id: "env-201".into(),
            action: SigningAction::Void {
                reason: "test".into(),
            },
            success: false,
            new_status: None,
            error_message: Some("Envelope not in valid state".into()),
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn signing_result_clone() {
        let result = SigningResult {
            envelope_id: "env-cl".into(),
            action: SigningAction::Resend,
            success: true,
            new_status: None,
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        let cloned = result.clone();
        drop(result);
        assert_eq!(cloned.envelope_id, "env-cl");
    }

    #[test]
    fn signing_result_debug() {
        let result = SigningResult {
            envelope_id: "env-db".into(),
            action: SigningAction::Send,
            success: true,
            new_status: None,
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("SigningResult"));
    }

    #[test]
    fn signing_result_serialize_roundtrip() {
        let result = SigningResult {
            envelope_id: "env-sr".into(),
            action: SigningAction::Send,
            success: true,
            new_status: Some("sent".into()),
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: SigningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-sr");
        assert!(back.success);
    }

    // ===== SigningPolicy tests =====

    #[test]
    fn policy_permissive_allows_send() {
        let policy = SigningPolicy::new_permissive();
        assert_eq!(
            policy.check_action(&SigningAction::Send, "env-1"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_permissive_allows_resend() {
        let policy = SigningPolicy::new_permissive();
        assert_eq!(
            policy.check_action(&SigningAction::Resend, "env-1"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_permissive_allows_void() {
        let policy = SigningPolicy::new_permissive();
        let action = SigningAction::Void {
            reason: "ok".into(),
        };
        assert_eq!(
            policy.check_action(&action, "env-1"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_permissive_allows_correct() {
        let policy = SigningPolicy::new_permissive();
        assert_eq!(
            policy.check_action(&SigningAction::Correct, "env-1"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_readonly_denies_send() {
        let policy = SigningPolicy::new_readonly();
        let decision = policy.check_action(&SigningAction::Send, "env-1");
        assert!(decision.is_denied());
    }

    #[test]
    fn policy_readonly_denies_resend() {
        let policy = SigningPolicy::new_readonly();
        let decision = policy.check_action(&SigningAction::Resend, "env-1");
        assert!(decision.is_denied());
    }

    #[test]
    fn policy_readonly_denies_void() {
        let policy = SigningPolicy::new_readonly();
        let action = SigningAction::Void {
            reason: "test".into(),
        };
        let decision = policy.check_action(&action, "env-1");
        assert!(decision.is_denied());
    }

    #[test]
    fn policy_readonly_denies_correct() {
        let policy = SigningPolicy::new_readonly();
        let decision = policy.check_action(&SigningAction::Correct, "env-1");
        assert!(decision.is_denied());
    }

    #[test]
    fn policy_blocked_envelope_denies() {
        let mut policy = SigningPolicy::new_permissive();
        policy.blocked_envelope_ids.insert("blocked-env".into());
        let decision = policy.check_action(&SigningAction::Send, "blocked-env");
        assert!(decision.is_denied());
        if let SigningDecision::Deny { reason } = &decision {
            assert!(reason.contains("blocked-env"));
        }
    }

    #[test]
    fn policy_blocked_allows_other_envelopes() {
        let mut policy = SigningPolicy::new_permissive();
        policy.blocked_envelope_ids.insert("blocked-env".into());
        assert_eq!(
            policy.check_action(&SigningAction::Send, "other-env"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_require_approval_for_send() {
        let mut policy = SigningPolicy::new_permissive();
        policy.require_approval_for_send = true;
        let decision = policy.check_action(&SigningAction::Send, "env-1");
        assert!(decision.requires_approval());
    }

    #[test]
    fn policy_require_approval_for_void() {
        let mut policy = SigningPolicy::new_permissive();
        policy.require_approval_for_void = true;
        let action = SigningAction::Void {
            reason: "test".into(),
        };
        let decision = policy.check_action(&action, "env-1");
        assert!(decision.requires_approval());
    }

    #[test]
    fn policy_resend_no_approval_even_when_send_needs_approval() {
        let mut policy = SigningPolicy::new_permissive();
        policy.require_approval_for_send = true;
        assert_eq!(
            policy.check_action(&SigningAction::Resend, "env-1"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_clone() {
        let policy = SigningPolicy::new_permissive();
        let cloned = policy.clone();
        drop(policy);
        assert!(cloned.allow_send);
    }

    #[test]
    fn policy_debug() {
        let dbg = format!("{:?}", SigningPolicy::new_permissive());
        assert!(dbg.contains("SigningPolicy"));
    }

    #[test]
    fn policy_serialize_roundtrip() {
        let mut policy = SigningPolicy::new_permissive();
        policy.max_sends_per_hour = Some(50);
        let json = serde_json::to_string(&policy).unwrap();
        let back: SigningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_sends_per_hour, Some(50));
        assert!(back.allow_send);
    }

    #[test]
    fn policy_permissive_fields() {
        let p = SigningPolicy::new_permissive();
        assert!(p.allow_send);
        assert!(p.allow_resend);
        assert!(p.allow_void);
        assert!(!p.require_approval_for_send);
        assert!(!p.require_approval_for_void);
        assert!(p.max_sends_per_hour.is_none());
        assert!(p.blocked_envelope_ids.is_empty());
    }

    #[test]
    fn policy_readonly_fields() {
        let p = SigningPolicy::new_readonly();
        assert!(!p.allow_send);
        assert!(!p.allow_resend);
        assert!(!p.allow_void);
        assert!(p.blocked_envelope_ids.is_empty());
    }

    #[test]
    fn policy_deny_send_not_void() {
        let mut policy = SigningPolicy::new_permissive();
        policy.allow_send = false;
        assert!(policy.check_action(&SigningAction::Send, "e").is_denied());
        let void_action = SigningAction::Void { reason: "x".into() };
        assert_eq!(
            policy.check_action(&void_action, "e"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_deny_void_not_send() {
        let mut policy = SigningPolicy::new_permissive();
        policy.allow_void = false;
        let void_action = SigningAction::Void { reason: "x".into() };
        assert!(policy.check_action(&void_action, "e").is_denied());
        assert_eq!(
            policy.check_action(&SigningAction::Send, "e"),
            SigningDecision::Allow,
        );
    }

    #[test]
    fn policy_correct_denied_when_send_denied() {
        let mut policy = SigningPolicy::new_permissive();
        policy.allow_send = false;
        assert!(
            policy
                .check_action(&SigningAction::Correct, "e")
                .is_denied()
        );
    }

    // ===== SigningDecision tests =====

    #[test]
    fn decision_allow_is_allowed() {
        assert!(SigningDecision::Allow.is_allowed());
    }

    #[test]
    fn decision_allow_not_denied() {
        assert!(!SigningDecision::Allow.is_denied());
    }

    #[test]
    fn decision_allow_no_approval() {
        assert!(!SigningDecision::Allow.requires_approval());
    }

    #[test]
    fn decision_deny_is_denied() {
        let d = SigningDecision::Deny {
            reason: "nope".into(),
        };
        assert!(d.is_denied());
    }

    #[test]
    fn decision_deny_not_allowed() {
        let d = SigningDecision::Deny {
            reason: "nope".into(),
        };
        assert!(!d.is_allowed());
    }

    #[test]
    fn decision_approval_requires_approval() {
        let d = SigningDecision::RequireApproval {
            reason: "check".into(),
        };
        assert!(d.requires_approval());
    }

    #[test]
    fn decision_approval_not_allowed() {
        let d = SigningDecision::RequireApproval {
            reason: "check".into(),
        };
        assert!(!d.is_allowed());
    }

    #[test]
    fn decision_approval_not_denied() {
        let d = SigningDecision::RequireApproval {
            reason: "check".into(),
        };
        assert!(!d.is_denied());
    }

    #[test]
    fn decision_display_allow() {
        assert_eq!(SigningDecision::Allow.to_string(), "allowed");
    }

    #[test]
    fn decision_display_deny() {
        let d = SigningDecision::Deny {
            reason: "blocked".into(),
        };
        assert_eq!(d.to_string(), "denied: blocked");
    }

    #[test]
    fn decision_display_require_approval() {
        let d = SigningDecision::RequireApproval {
            reason: "high risk".into(),
        };
        assert_eq!(d.to_string(), "requires approval: high risk");
    }

    #[test]
    fn decision_clone() {
        let d = SigningDecision::Deny {
            reason: "test".into(),
        };
        let cloned = d.clone();
        drop(d);
        assert!(cloned.is_denied());
    }

    #[test]
    fn decision_equality() {
        assert_eq!(SigningDecision::Allow, SigningDecision::Allow);
    }

    #[test]
    fn decision_inequality() {
        assert_ne!(
            SigningDecision::Allow,
            SigningDecision::Deny { reason: "x".into() },
        );
    }

    #[test]
    fn decision_serialize_roundtrip() {
        let d = SigningDecision::RequireApproval {
            reason: "test".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: SigningDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    // ===== SigningValidator tests =====

    #[test]
    fn validator_default() {
        let v = SigningValidator::default();
        assert_eq!(v.max_reason_length, 200);
        assert_eq!(v.max_subject_length, 100);
        assert_eq!(v.max_expiration_days, 120);
    }

    #[test]
    fn validator_validate_send_ok() {
        let v = SigningValidator::default();
        let req = SendRequest {
            envelope_id: "env-1".into(),
            notification_override: None,
        };
        assert!(v.validate_send(&req).is_ok());
    }

    #[test]
    fn validator_validate_send_empty_id() {
        let v = SigningValidator::default();
        let req = SendRequest {
            envelope_id: String::new(),
            notification_override: None,
        };
        assert_eq!(
            v.validate_send(&req).unwrap_err(),
            SigningValidationError::EmptyEnvelopeId,
        );
    }

    #[test]
    fn validator_validate_send_with_valid_notification() {
        let v = SigningValidator::default();
        let req = SendRequest {
            envelope_id: "env-1".into(),
            notification_override: Some(NotificationConfig {
                subject_override: Some("Short".into()),
                expiration_days: Some(30),
                ..NotificationConfig::default()
            }),
        };
        assert!(v.validate_send(&req).is_ok());
    }

    #[test]
    fn validator_validate_send_subject_too_long() {
        let v = SigningValidator::default();
        let req = SendRequest {
            envelope_id: "env-1".into(),
            notification_override: Some(NotificationConfig {
                subject_override: Some("x".repeat(101)),
                ..NotificationConfig::default()
            }),
        };
        let err = v.validate_send(&req).unwrap_err();
        assert!(matches!(err, SigningValidationError::SubjectTooLong { .. }));
    }

    #[test]
    fn validator_validate_send_expiration_zero() {
        let v = SigningValidator::default();
        let req = SendRequest {
            envelope_id: "env-1".into(),
            notification_override: Some(NotificationConfig {
                expiration_days: Some(0),
                ..NotificationConfig::default()
            }),
        };
        let err = v.validate_send(&req).unwrap_err();
        assert!(matches!(
            err,
            SigningValidationError::InvalidExpirationDays { .. }
        ));
    }

    #[test]
    fn validator_validate_send_expiration_too_high() {
        let v = SigningValidator::default();
        let req = SendRequest {
            envelope_id: "env-1".into(),
            notification_override: Some(NotificationConfig {
                expiration_days: Some(121),
                ..NotificationConfig::default()
            }),
        };
        let err = v.validate_send(&req).unwrap_err();
        assert!(matches!(
            err,
            SigningValidationError::InvalidExpirationDays { .. }
        ));
    }

    #[test]
    fn validator_validate_void_ok() {
        let v = SigningValidator::default();
        let req = VoidRequest {
            envelope_id: "env-1".into(),
            reason: "Not needed".into(),
        };
        assert!(v.validate_void(&req).is_ok());
    }

    #[test]
    fn validator_validate_void_empty_id() {
        let v = SigningValidator::default();
        let req = VoidRequest {
            envelope_id: String::new(),
            reason: "test".into(),
        };
        assert_eq!(
            v.validate_void(&req).unwrap_err(),
            SigningValidationError::EmptyEnvelopeId,
        );
    }

    #[test]
    fn validator_validate_void_empty_reason() {
        let v = SigningValidator::default();
        let req = VoidRequest {
            envelope_id: "env-1".into(),
            reason: String::new(),
        };
        assert_eq!(
            v.validate_void(&req).unwrap_err(),
            SigningValidationError::EmptyReason,
        );
    }

    #[test]
    fn validator_validate_void_reason_too_long() {
        let v = SigningValidator::default();
        let req = VoidRequest {
            envelope_id: "env-1".into(),
            reason: "x".repeat(201),
        };
        let err = v.validate_void(&req).unwrap_err();
        assert!(matches!(err, SigningValidationError::ReasonTooLong { .. }));
    }

    #[test]
    fn validator_validate_notification_ok() {
        let v = SigningValidator::default();
        let config = NotificationConfig {
            subject_override: Some("Hello".into()),
            expiration_days: Some(60),
            ..NotificationConfig::default()
        };
        assert!(v.validate_notification(&config).is_ok());
    }

    #[test]
    fn validator_validate_notification_no_overrides() {
        let v = SigningValidator::default();
        assert!(
            v.validate_notification(&NotificationConfig::default())
                .is_ok()
        );
    }

    #[test]
    fn validator_validate_notification_subject_exactly_100() {
        let v = SigningValidator::default();
        let config = NotificationConfig {
            subject_override: Some("x".repeat(100)),
            ..NotificationConfig::default()
        };
        assert!(v.validate_notification(&config).is_ok());
    }

    #[test]
    fn validator_validate_notification_subject_101() {
        let v = SigningValidator::default();
        let config = NotificationConfig {
            subject_override: Some("x".repeat(101)),
            ..NotificationConfig::default()
        };
        let err = v.validate_notification(&config).unwrap_err();
        assert_eq!(
            err,
            SigningValidationError::SubjectTooLong {
                length: 101,
                max: 100,
            },
        );
    }

    #[test]
    fn validator_validate_notification_expiration_120() {
        let v = SigningValidator::default();
        let config = NotificationConfig {
            expiration_days: Some(120),
            ..NotificationConfig::default()
        };
        assert!(v.validate_notification(&config).is_ok());
    }

    #[test]
    fn validator_validate_notification_expiration_121() {
        let v = SigningValidator::default();
        let config = NotificationConfig {
            expiration_days: Some(121),
            ..NotificationConfig::default()
        };
        let err = v.validate_notification(&config).unwrap_err();
        assert_eq!(
            err,
            SigningValidationError::InvalidExpirationDays {
                days: 121,
                max: 120,
            },
        );
    }

    #[test]
    fn validator_custom_limits() {
        let v = SigningValidator {
            max_reason_length: 50,
            max_subject_length: 20,
            max_expiration_days: 30,
        };
        let req = VoidRequest {
            envelope_id: "env-1".into(),
            reason: "x".repeat(51),
        };
        let err = v.validate_void(&req).unwrap_err();
        assert_eq!(
            err,
            SigningValidationError::ReasonTooLong {
                length: 51,
                max: 50,
            },
        );
    }

    #[test]
    fn validator_custom_subject_limit() {
        let v = SigningValidator {
            max_subject_length: 10,
            ..SigningValidator::default()
        };
        let config = NotificationConfig {
            subject_override: Some("x".repeat(11)),
            ..NotificationConfig::default()
        };
        let err = v.validate_notification(&config).unwrap_err();
        assert_eq!(
            err,
            SigningValidationError::SubjectTooLong {
                length: 11,
                max: 10,
            },
        );
    }

    #[test]
    fn validator_custom_expiration_limit() {
        let v = SigningValidator {
            max_expiration_days: 7,
            ..SigningValidator::default()
        };
        let config = NotificationConfig {
            expiration_days: Some(8),
            ..NotificationConfig::default()
        };
        let err = v.validate_notification(&config).unwrap_err();
        assert_eq!(
            err,
            SigningValidationError::InvalidExpirationDays { days: 8, max: 7 },
        );
    }

    #[test]
    fn validator_clone() {
        let v = SigningValidator::default();
        let cloned = v.clone();
        assert_eq!(v.max_reason_length, cloned.max_reason_length);
        assert_eq!(cloned.max_reason_length, 200);
    }

    #[test]
    fn validator_debug() {
        let dbg = format!("{:?}", SigningValidator::default());
        assert!(dbg.contains("SigningValidator"));
    }

    #[test]
    fn validator_serialize_roundtrip() {
        let v = SigningValidator {
            max_reason_length: 150,
            max_subject_length: 80,
            max_expiration_days: 90,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: SigningValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_reason_length, 150);
        assert_eq!(back.max_subject_length, 80);
        assert_eq!(back.max_expiration_days, 90);
    }

    // ===== SigningValidationError tests =====

    #[test]
    fn validation_error_display_empty_id() {
        let err = SigningValidationError::EmptyEnvelopeId;
        assert_eq!(err.to_string(), "envelope ID must not be empty");
    }

    #[test]
    fn validation_error_display_empty_reason() {
        let err = SigningValidationError::EmptyReason;
        assert_eq!(err.to_string(), "void reason must not be empty");
    }

    #[test]
    fn validation_error_display_reason_too_long() {
        let err = SigningValidationError::ReasonTooLong {
            length: 250,
            max: 200,
        };
        assert_eq!(err.to_string(), "reason too long: 250 chars (max 200)");
    }

    #[test]
    fn validation_error_display_subject_too_long() {
        let err = SigningValidationError::SubjectTooLong {
            length: 120,
            max: 100,
        };
        assert_eq!(err.to_string(), "subject too long: 120 chars (max 100)");
    }

    #[test]
    fn validation_error_display_invalid_expiration() {
        let err = SigningValidationError::InvalidExpirationDays {
            days: 200,
            max: 120,
        };
        assert_eq!(
            err.to_string(),
            "invalid expiration days: 200 (must be 1..=120)",
        );
    }

    #[test]
    fn validation_error_display_blocked() {
        let err = SigningValidationError::BlockedEnvelope {
            envelope_id: "env-b".into(),
        };
        assert_eq!(err.to_string(), "envelope env-b is blocked by policy",);
    }

    #[test]
    fn validation_error_equality() {
        assert_eq!(
            SigningValidationError::EmptyEnvelopeId,
            SigningValidationError::EmptyEnvelopeId,
        );
    }

    #[test]
    fn validation_error_inequality() {
        assert_ne!(
            SigningValidationError::EmptyEnvelopeId,
            SigningValidationError::EmptyReason,
        );
    }

    #[test]
    fn validation_error_clone() {
        let err = SigningValidationError::ReasonTooLong {
            length: 300,
            max: 200,
        };
        let cloned = err.clone();
        drop(err);
        assert!(matches!(
            cloned,
            SigningValidationError::ReasonTooLong { .. }
        ));
    }

    #[test]
    fn validation_error_debug() {
        let dbg = format!("{:?}", SigningValidationError::EmptyEnvelopeId);
        assert!(dbg.contains("EmptyEnvelopeId"));
    }

    #[test]
    fn validation_error_serialize_roundtrip() {
        let err = SigningValidationError::ReasonTooLong {
            length: 250,
            max: 200,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: SigningValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }

    #[test]
    fn validation_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(SigningValidationError::EmptyEnvelopeId);
        assert!(err.to_string().contains("envelope ID"));
    }

    // ===== SigningAuditEvent tests =====

    #[test]
    fn audit_event_new() {
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Send,
            "env-1",
            true,
            "Envelope sent successfully",
        );
        assert_eq!(event.timestamp, "2026-03-09T10:00:00Z");
        assert_eq!(event.action, SigningAction::Send);
        assert_eq!(event.envelope_id, "env-1");
        assert!(event.was_allowed);
        assert_eq!(event.details, "Envelope sent successfully");
    }

    #[test]
    fn audit_event_denied() {
        let event = SigningAuditEvent::new(
            "2026-03-09T11:00:00Z",
            SigningAction::Void {
                reason: "cancelled".into(),
            },
            "env-blocked",
            false,
            "Blocked by policy",
        );
        assert!(!event.was_allowed);
        assert_eq!(event.envelope_id, "env-blocked");
    }

    #[test]
    fn audit_event_display_allowed() {
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Send,
            "env-1",
            true,
            "OK",
        );
        let display = event.to_string();
        assert!(display.contains("ALLOWED"));
        assert!(display.contains("send"));
        assert!(display.contains("env-1"));
        assert!(display.contains("OK"));
    }

    #[test]
    fn audit_event_display_denied() {
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Resend,
            "env-2",
            false,
            "Not permitted",
        );
        let display = event.to_string();
        assert!(display.contains("DENIED"));
        assert!(display.contains("resend"));
        assert!(display.contains("env-2"));
    }

    #[test]
    fn audit_event_clone() {
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Correct,
            "env-c",
            true,
            "corrected",
        );
        let cloned = event.clone();
        drop(event);
        assert_eq!(cloned.envelope_id, "env-c");
    }

    #[test]
    fn audit_event_debug() {
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Send,
            "env-d",
            true,
            "debug",
        );
        let dbg = format!("{event:?}");
        assert!(dbg.contains("SigningAuditEvent"));
    }

    #[test]
    fn audit_event_serialize_roundtrip() {
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Void {
                reason: "test".into(),
            },
            "env-sr",
            false,
            "round trip",
        );
        let json = serde_json::to_string(&event).unwrap();
        let back: SigningAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-sr");
        assert!(!back.was_allowed);
    }

    #[test]
    fn audit_event_with_void_action() {
        let event = SigningAuditEvent::new(
            "2026-03-09T12:00:00Z",
            SigningAction::Void {
                reason: "expired contract".into(),
            },
            "env-void",
            true,
            "Voided successfully",
        );
        assert!(event.action.is_destructive());
        assert!(event.was_allowed);
    }

    // ===== Integration / cross-type tests =====

    #[test]
    fn policy_check_then_audit() {
        let policy = SigningPolicy::new_permissive();
        let action = SigningAction::Send;
        let envelope_id = "env-flow-1";
        let decision = policy.check_action(&action, envelope_id);
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            action,
            envelope_id,
            decision.is_allowed(),
            format!("Decision: {decision}"),
        );
        assert!(event.was_allowed);
        assert!(event.details.contains("allowed"));
    }

    #[test]
    fn policy_deny_then_audit() {
        let policy = SigningPolicy::new_readonly();
        let action = SigningAction::Send;
        let envelope_id = "env-flow-2";
        let decision = policy.check_action(&action, envelope_id);
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            action,
            envelope_id,
            decision.is_allowed(),
            format!("Decision: {decision}"),
        );
        assert!(!event.was_allowed);
        assert!(event.details.contains("denied"));
    }

    #[test]
    fn send_request_validate_then_policy_check() {
        let req = SendRequest {
            envelope_id: "env-validated".into(),
            notification_override: None,
        };
        assert!(req.validate().is_ok());

        let policy = SigningPolicy::new_permissive();
        let decision = policy.check_action(&SigningAction::Send, &req.envelope_id);
        assert!(decision.is_allowed());
    }

    #[test]
    fn void_request_validate_then_policy_check() {
        let req = VoidRequest {
            envelope_id: "env-void-flow".into(),
            reason: "Not needed anymore".into(),
        };
        assert!(req.validate().is_ok());

        let mut policy = SigningPolicy::new_permissive();
        policy.require_approval_for_void = true;
        let action = SigningAction::Void {
            reason: req.reason.clone(),
        };
        let decision = policy.check_action(&action, &req.envelope_id);
        assert!(decision.requires_approval());
    }

    #[test]
    fn full_signing_flow() {
        // 1. Create request
        let req = SendRequest {
            envelope_id: "env-full-flow".into(),
            notification_override: Some(NotificationConfig {
                subject_override: Some("Please sign".into()),
                reminder_enabled: true,
                reminder_delay_days: Some(2),
                ..NotificationConfig::default()
            }),
        };

        // 2. Validate
        let validator = SigningValidator::default();
        assert!(validator.validate_send(&req).is_ok());

        // 3. Check policy
        let policy = SigningPolicy::new_permissive();
        let action = SigningAction::Send;
        let decision = policy.check_action(&action, &req.envelope_id);
        assert!(decision.is_allowed());

        // 4. Record result
        let result = SigningResult {
            envelope_id: req.envelope_id.clone(),
            action: action.clone(),
            success: true,
            new_status: Some("sent".into()),
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(result.success);

        // 5. Audit
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            action,
            &req.envelope_id,
            true,
            "Full flow completed",
        );
        assert!(event.was_allowed);
    }

    #[test]
    fn full_void_flow() {
        // 1. Create request
        let req = VoidRequest {
            envelope_id: "env-void-full".into(),
            reason: "Contract superseded".into(),
        };

        // 2. Validate
        let validator = SigningValidator::default();
        assert!(validator.validate_void(&req).is_ok());

        // 3. Check policy
        let policy = SigningPolicy::new_permissive();
        let action = SigningAction::Void {
            reason: req.reason.clone(),
        };
        let decision = policy.check_action(&action, &req.envelope_id);
        assert!(decision.is_allowed());
        assert!(action.is_destructive());

        // 4. Record result
        let result = SigningResult {
            envelope_id: req.envelope_id.clone(),
            action: action.clone(),
            success: true,
            new_status: Some("voided".into()),
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(result.success);
        assert_eq!(result.new_status, Some("voided".into()));

        // 5. Audit
        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            action,
            &req.envelope_id,
            true,
            "Envelope voided",
        );
        assert!(event.was_allowed);
    }

    #[test]
    fn blocked_envelope_full_flow() {
        let mut policy = SigningPolicy::new_permissive();
        policy.blocked_envelope_ids.insert("env-locked".into());

        let req = SendRequest {
            envelope_id: "env-locked".into(),
            notification_override: None,
        };
        assert!(req.validate().is_ok());

        let decision = policy.check_action(&SigningAction::Send, &req.envelope_id);
        assert!(decision.is_denied());

        let event = SigningAuditEvent::new(
            "2026-03-09T10:00:00Z",
            SigningAction::Send,
            &req.envelope_id,
            false,
            format!("Policy: {decision}"),
        );
        assert!(!event.was_allowed);
        assert!(event.details.contains("blocked"));
    }

    #[test]
    fn multiple_blocked_envelopes() {
        let mut policy = SigningPolicy::new_permissive();
        policy.blocked_envelope_ids.insert("e1".into());
        policy.blocked_envelope_ids.insert("e2".into());
        policy.blocked_envelope_ids.insert("e3".into());

        assert!(policy.check_action(&SigningAction::Send, "e1").is_denied());
        assert!(policy.check_action(&SigningAction::Send, "e2").is_denied());
        assert!(policy.check_action(&SigningAction::Send, "e3").is_denied());
        assert!(policy.check_action(&SigningAction::Send, "e4").is_allowed());
    }

    #[test]
    fn signing_result_with_error() {
        let result = SigningResult {
            envelope_id: "env-err".into(),
            action: SigningAction::Send,
            success: false,
            new_status: None,
            error_message: Some("Envelope already sent".into()),
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(!result.success);
        assert!(
            result
                .error_message
                .as_ref()
                .unwrap()
                .contains("already sent")
        );
    }

    #[test]
    fn signing_result_resend_success() {
        let result = SigningResult {
            envelope_id: "env-resend".into(),
            action: SigningAction::Resend,
            success: true,
            new_status: None,
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(result.success);
        assert!(result.new_status.is_none());
    }

    #[test]
    fn signing_result_correct_success() {
        let result = SigningResult {
            envelope_id: "env-correct".into(),
            action: SigningAction::Correct,
            success: true,
            new_status: Some("sent".into()),
            error_message: None,
            timestamp: "2026-03-09T10:00:00Z".into(),
        };
        assert!(result.success);
    }

    #[test]
    fn notification_config_debug() {
        let dbg = format!("{:?}", NotificationConfig::default());
        assert!(dbg.contains("NotificationConfig"));
    }

    #[test]
    fn validation_error_expiration_zero_display() {
        let err = SigningValidationError::InvalidExpirationDays { days: 0, max: 120 };
        assert!(err.to_string().contains('0'));
        assert!(err.to_string().contains("120"));
    }

    #[test]
    fn resend_request_empty_recipients_list() {
        let req = ResendRequest {
            envelope_id: "env-empty-list".into(),
            recipient_ids: Some(vec![]),
        };
        assert!(req.recipient_ids.as_ref().unwrap().is_empty());
    }

    #[test]
    fn policy_max_sends_per_hour() {
        let mut policy = SigningPolicy::new_permissive();
        policy.max_sends_per_hour = Some(100);
        assert_eq!(policy.max_sends_per_hour, Some(100));
        // Policy check itself doesn't enforce rate limits — that's external.
        assert!(policy.check_action(&SigningAction::Send, "e").is_allowed());
    }

    #[test]
    fn audit_event_resend_display() {
        let event = SigningAuditEvent::new(
            "2026-03-09T14:00:00Z",
            SigningAction::Resend,
            "env-resend-audit",
            true,
            "Notifications resent to 3 recipients",
        );
        let display = event.to_string();
        assert!(display.contains("ALLOWED"));
        assert!(display.contains("resend"));
        assert!(display.contains("env-resend-audit"));
        assert!(display.contains("3 recipients"));
    }

    #[test]
    fn audit_event_correct_display() {
        let event = SigningAuditEvent::new(
            "2026-03-09T15:00:00Z",
            SigningAction::Correct,
            "env-correct-audit",
            true,
            "Recipient email updated",
        );
        let display = event.to_string();
        assert!(display.contains("correct"));
        assert!(display.contains("env-correct-audit"));
    }
}
