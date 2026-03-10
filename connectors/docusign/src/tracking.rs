//! `DocuSign` envelope signature status tracking.
//!
//! Tracks envelope progress (delivered/signed/completed/declined/voided),
//! recipient-level status (without leaking PII), and provides webhook
//! ingestion for real-time status updates.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Envelope status tracking
// ---------------------------------------------------------------------------

/// High-level status information for a `DocuSign` envelope.
///
/// Tracks the full lifecycle: created -> sent -> delivered -> signed ->
/// completed, or declined/voided at any point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeStatusInfo {
    /// The unique envelope identifier.
    pub envelope_id: String,
    /// Current status (e.g. "created", "sent", "delivered", "completed",
    /// "declined", "voided").
    pub status: String,
    /// Envelope subject line, if available.
    pub subject: Option<String>,
    /// When the envelope was created (ISO-8601).
    pub created_at: String,
    /// When the envelope was sent (ISO-8601).
    pub sent_at: Option<String>,
    /// When the envelope was completed (ISO-8601).
    pub completed_at: Option<String>,
    /// When the envelope was voided (ISO-8601).
    pub voided_at: Option<String>,
    /// Reason the envelope was voided.
    pub voided_reason: Option<String>,
    /// Number of recipients who have completed signing.
    pub recipients_completed: u32,
    /// Total number of recipients.
    pub recipients_total: u32,
    /// Number of documents in the envelope.
    pub documents_count: u32,
}

impl EnvelopeStatusInfo {
    /// Returns the completion progress as a percentage (0-100).
    ///
    /// Returns 100 if the envelope status is "completed" or "voided".
    /// Returns 0 if there are no recipients.
    /// Otherwise returns `(recipients_completed / recipients_total) * 100`.
    #[must_use]
    pub fn progress_percent(&self) -> u32 {
        if self.status == "completed" || self.status == "voided" {
            return 100;
        }
        if self.recipients_total == 0 {
            return 0;
        }
        let pct = (self.recipients_completed * 100) / self.recipients_total;
        pct.min(100)
    }

    /// Returns `true` if the envelope has reached a terminal completed state.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.status == "completed"
    }

    /// Returns `true` if the envelope has been voided.
    #[must_use]
    pub fn is_voided(&self) -> bool {
        self.status == "voided"
    }
}

// ---------------------------------------------------------------------------
// Recipient status (privacy-safe — NO email or name)
// ---------------------------------------------------------------------------

/// Status of a single recipient in an envelope.
///
/// IMPORTANT: This struct intentionally omits email and name fields
/// to prevent PII leakage through the tracking interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientStatus {
    /// The recipient identifier (opaque ID).
    pub recipient_id: String,
    /// The recipient's role (e.g. "signer", "`carbon_copy`", "`in_person_signer`").
    pub role: String,
    /// Current status of this recipient.
    pub status: RecipientStatusType,
    /// Routing order (1-based).
    pub routing_order: u32,
    /// When the recipient signed (ISO-8601).
    pub signed_at: Option<String>,
    /// When the recipient declined (ISO-8601).
    pub declined_at: Option<String>,
    /// When the envelope was delivered to the recipient (ISO-8601).
    pub delivered_at: Option<String>,
}

/// The possible states for a recipient in the signing workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecipientStatusType {
    /// Recipient record has been created but not yet sent.
    Created,
    /// Envelope has been sent to the recipient.
    Sent,
    /// Envelope has been delivered (opened) by the recipient.
    Delivered,
    /// Recipient has signed the document(s).
    Signed,
    /// Recipient has declined to sign.
    Declined,
    /// Recipient failed authentication.
    AuthenticationFailed,
    /// Auto-response was received (e.g. out-of-office).
    AutoResponded,
}

impl RecipientStatusType {
    /// Returns `true` if this status is terminal (no further transitions).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Declined | Self::AuthenticationFailed
        )
    }

    /// Returns `true` if this status represents a successful outcome.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(self, Self::Signed)
    }

    /// Returns the string representation of this status.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Signed => "signed",
            Self::Declined => "declined",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AutoResponded => "auto_responded",
        }
    }
}

impl fmt::Display for RecipientStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RecipientStatusType {
    type Err = TrackingValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created" => Ok(Self::Created),
            "sent" => Ok(Self::Sent),
            "delivered" => Ok(Self::Delivered),
            "signed" | "completed" => Ok(Self::Signed),
            "declined" => Ok(Self::Declined),
            "authentication_failed" | "authenticationfailed" => Ok(Self::AuthenticationFailed),
            "auto_responded" | "autoresponded" => Ok(Self::AutoResponded),
            _ => Err(TrackingValidationError::InvalidStatus(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Envelope list query (builder pattern)
// ---------------------------------------------------------------------------

/// Query parameters for listing envelopes with filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeListQuery {
    /// Filter by one or more statuses (e.g. "completed", "sent").
    pub status_filter: Option<Vec<String>>,
    /// Start of date range filter (ISO-8601).
    pub from_date: Option<String>,
    /// End of date range filter (ISO-8601).
    pub to_date: Option<String>,
    /// Free-text search within envelope subjects.
    pub search_text: Option<String>,
    /// Restrict to a specific folder.
    pub folder_id: Option<String>,
    /// Maximum results to return (default 25, max 100).
    pub limit: u32,
    /// Offset for pagination.
    pub offset: u32,
}

impl Default for EnvelopeListQuery {
    fn default() -> Self {
        Self {
            status_filter: None,
            from_date: None,
            to_date: None,
            search_text: None,
            folder_id: None,
            limit: 25,
            offset: 0,
        }
    }
}

impl EnvelopeListQuery {
    /// Creates a new query with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a status filter.
    #[must_use]
    pub fn with_status(mut self, status: &str) -> Self {
        self.status_filter
            .get_or_insert_with(Vec::new)
            .push(status.to_string());
        self
    }

    /// Sets the date range filter.
    #[must_use]
    pub fn with_date_range(mut self, from: &str, to: &str) -> Self {
        self.from_date = Some(from.to_string());
        self.to_date = Some(to.to_string());
        self
    }

    /// Sets the search text filter.
    #[must_use]
    pub fn with_search(mut self, text: &str) -> Self {
        self.search_text = Some(text.to_string());
        self
    }

    /// Sets the result limit.
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Sets the pagination offset.
    #[must_use]
    pub const fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Sets the folder ID filter.
    #[must_use]
    pub fn with_folder(mut self, folder_id: &str) -> Self {
        self.folder_id = Some(folder_id.to_string());
        self
    }

    /// Validates the query parameters.
    ///
    /// # Errors
    ///
    /// Returns `TrackingValidationError` if:
    /// - `limit` is 0 or greater than 100
    /// - `from_date` is set without `to_date` or vice versa
    /// - An invalid status string is specified
    pub fn validate(&self) -> Result<(), TrackingValidationError> {
        if self.limit == 0 || self.limit > 100 {
            return Err(TrackingValidationError::InvalidLimit(self.limit));
        }
        // If one date is set, the other must also be set.
        if self.from_date.is_some() != self.to_date.is_some() {
            return Err(TrackingValidationError::InvalidDateRange(
                "both from_date and to_date must be set together".to_string(),
            ));
        }
        // Validate status strings if present.
        if let Some(statuses) = &self.status_filter {
            let allowed = TrackingValidator::default_allowed_statuses();
            for s in statuses {
                if !allowed.contains(&s.as_str()) {
                    return Err(TrackingValidationError::InvalidStatus(s.clone()));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Envelope list page (response)
// ---------------------------------------------------------------------------

/// A paginated page of envelope status results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeListPage {
    /// The envelope status entries on this page.
    pub envelopes: Vec<EnvelopeStatusInfo>,
    /// Total number of envelopes matching the query.
    pub total_count: u32,
    /// Number of results in this page.
    pub result_set_size: u32,
    /// Start position (0-based offset).
    pub start_position: u32,
    /// End position (inclusive).
    pub end_position: u32,
}

impl EnvelopeListPage {
    /// Returns `true` if there are more pages available.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.end_position + 1 < self.total_count
    }

    /// Returns `true` if this page contains no envelopes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Webhook types
// ---------------------------------------------------------------------------

/// A webhook payload representing a real-time status update from `DocuSign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusWebhook {
    /// The type of event (e.g. "envelope-sent", "recipient-signed").
    pub event_type: String,
    /// The envelope this event pertains to.
    pub envelope_id: String,
    /// The new status.
    pub status: String,
    /// When the event occurred (ISO-8601).
    pub timestamp: String,
    /// Per-recipient status updates included in this event.
    pub recipient_statuses: Vec<RecipientStatus>,
}

impl StatusWebhook {
    /// Validates the webhook payload.
    ///
    /// # Errors
    ///
    /// Returns `TrackingValidationError` if:
    /// - `envelope_id` is empty
    /// - `event_type` is not a known webhook event type
    pub fn validate(&self) -> Result<(), TrackingValidationError> {
        if self.envelope_id.is_empty() {
            return Err(TrackingValidationError::EmptyEnvelopeId);
        }
        // Verify event_type is known.
        self.event_type
            .parse::<WebhookEventType>()
            .map_err(|_| TrackingValidationError::UnknownWebhookEvent(self.event_type.clone()))?;
        Ok(())
    }
}

/// Known webhook event types from `DocuSign` Connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebhookEventType {
    /// Envelope has been sent to recipients.
    EnvelopeSent,
    /// Envelope has been delivered (opened) by a recipient.
    EnvelopeDelivered,
    /// All recipients have completed — envelope is done.
    EnvelopeCompleted,
    /// A recipient declined to sign.
    EnvelopeDeclined,
    /// The envelope was voided by the sender.
    EnvelopeVoided,
    /// A specific recipient signed.
    RecipientSigned,
    /// A specific recipient declined.
    RecipientDeclined,
    /// A specific recipient received delivery.
    RecipientDelivered,
}

impl WebhookEventType {
    /// Returns the canonical string key for this event type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EnvelopeSent => "envelope-sent",
            Self::EnvelopeDelivered => "envelope-delivered",
            Self::EnvelopeCompleted => "envelope-completed",
            Self::EnvelopeDeclined => "envelope-declined",
            Self::EnvelopeVoided => "envelope-voided",
            Self::RecipientSigned => "recipient-signed",
            Self::RecipientDeclined => "recipient-declined",
            Self::RecipientDelivered => "recipient-delivered",
        }
    }

    /// Returns all known event types.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::EnvelopeSent,
            Self::EnvelopeDelivered,
            Self::EnvelopeCompleted,
            Self::EnvelopeDeclined,
            Self::EnvelopeVoided,
            Self::RecipientSigned,
            Self::RecipientDeclined,
            Self::RecipientDelivered,
        ]
    }

    /// Returns `true` if this is an envelope-level event.
    #[must_use]
    pub const fn is_envelope_event(&self) -> bool {
        matches!(
            self,
            Self::EnvelopeSent
                | Self::EnvelopeDelivered
                | Self::EnvelopeCompleted
                | Self::EnvelopeDeclined
                | Self::EnvelopeVoided
        )
    }

    /// Returns `true` if this is a recipient-level event.
    #[must_use]
    pub const fn is_recipient_event(&self) -> bool {
        matches!(
            self,
            Self::RecipientSigned | Self::RecipientDeclined | Self::RecipientDelivered
        )
    }

    /// Returns `true` if this event indicates a terminal/final state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::EnvelopeCompleted | Self::EnvelopeDeclined | Self::EnvelopeVoided
        )
    }
}

impl fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for WebhookEventType {
    type Err = TrackingValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "envelope-sent" => Ok(Self::EnvelopeSent),
            "envelope-delivered" => Ok(Self::EnvelopeDelivered),
            "envelope-completed" => Ok(Self::EnvelopeCompleted),
            "envelope-declined" => Ok(Self::EnvelopeDeclined),
            "envelope-voided" => Ok(Self::EnvelopeVoided),
            "recipient-signed" => Ok(Self::RecipientSigned),
            "recipient-declined" => Ok(Self::RecipientDeclined),
            "recipient-delivered" => Ok(Self::RecipientDelivered),
            _ => Err(TrackingValidationError::UnknownWebhookEvent(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates tracking queries and webhook payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingValidator {
    /// Maximum allowed limit for list queries.
    pub max_limit: u32,
    /// Maximum allowed date range in days.
    pub max_date_range_days: u32,
    /// Set of allowed envelope status strings.
    pub allowed_statuses: Vec<String>,
}

impl Default for TrackingValidator {
    fn default() -> Self {
        Self {
            max_limit: 100,
            max_date_range_days: 365,
            allowed_statuses: Self::default_allowed_statuses()
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }
}

impl TrackingValidator {
    /// Returns the default set of allowed envelope statuses.
    #[must_use]
    pub fn default_allowed_statuses() -> Vec<&'static str> {
        vec![
            "created",
            "sent",
            "delivered",
            "signed",
            "completed",
            "declined",
            "voided",
            "deleted",
            "template",
            "any",
        ]
    }

    /// Validates an envelope list query.
    ///
    /// # Errors
    ///
    /// Returns `TrackingValidationError` if the query is invalid.
    pub fn validate_query(&self, query: &EnvelopeListQuery) -> Result<(), TrackingValidationError> {
        if query.limit == 0 || query.limit > self.max_limit {
            return Err(TrackingValidationError::InvalidLimit(query.limit));
        }
        if query.from_date.is_some() != query.to_date.is_some() {
            return Err(TrackingValidationError::InvalidDateRange(
                "both from_date and to_date must be set together".to_string(),
            ));
        }
        if let Some(statuses) = &query.status_filter {
            for s in statuses {
                if !self.allowed_statuses.iter().any(|a| a == s) {
                    return Err(TrackingValidationError::InvalidStatus(s.clone()));
                }
            }
        }
        Ok(())
    }

    /// Validates a webhook payload.
    ///
    /// # Errors
    ///
    /// Returns `TrackingValidationError` if the webhook is invalid.
    pub fn validate_webhook(&self, webhook: &StatusWebhook) -> Result<(), TrackingValidationError> {
        webhook.validate()
    }
}

/// Errors that can occur during tracking validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackingValidationError {
    /// The limit value is invalid (must be 1-100).
    InvalidLimit(u32),
    /// The date range is invalid.
    InvalidDateRange(String),
    /// An unrecognized envelope status was specified.
    InvalidStatus(String),
    /// The envelope ID is empty.
    EmptyEnvelopeId,
    /// An unknown webhook event type was received.
    UnknownWebhookEvent(String),
}

impl fmt::Display for TrackingValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(limit) => {
                write!(f, "invalid limit: {limit} (must be between 1 and 100)")
            }
            Self::InvalidDateRange(msg) => write!(f, "invalid date range: {msg}"),
            Self::InvalidStatus(status) => write!(f, "invalid status: {status}"),
            Self::EmptyEnvelopeId => write!(f, "envelope ID must not be empty"),
            Self::UnknownWebhookEvent(event) => write!(f, "unknown webhook event: {event}"),
        }
    }
}

impl std::error::Error for TrackingValidationError {}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// The type of action recorded in a tracking audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackingAction {
    /// A query was executed.
    Query,
    /// A webhook was received and processed.
    WebhookReceived,
}

impl fmt::Display for TrackingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query => f.write_str("query"),
            Self::WebhookReceived => f.write_str("webhook_received"),
        }
    }
}

/// An audit log entry for tracking operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingAuditEvent {
    /// When the action occurred (ISO-8601).
    pub timestamp: String,
    /// What kind of action was performed.
    pub action: TrackingAction,
    /// Number of envelopes involved.
    pub envelope_count: u32,
    /// Whether any filter was used in the action.
    pub filter_used: bool,
}

impl TrackingAuditEvent {
    /// Creates a new audit event for a query action.
    #[must_use]
    pub fn for_query(timestamp: &str, envelope_count: u32, filter_used: bool) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            action: TrackingAction::Query,
            envelope_count,
            filter_used,
        }
    }

    /// Creates a new audit event for a webhook received action.
    #[must_use]
    pub fn for_webhook(timestamp: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            action: TrackingAction::WebhookReceived,
            envelope_count: 1,
            filter_used: false,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper constructors --

    fn sample_envelope_status() -> EnvelopeStatusInfo {
        EnvelopeStatusInfo {
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            subject: Some("Please sign this NDA".to_string()),
            created_at: "2026-01-15T09:00:00Z".to_string(),
            sent_at: Some("2026-01-15T10:00:00Z".to_string()),
            completed_at: None,
            voided_at: None,
            voided_reason: None,
            recipients_completed: 1,
            recipients_total: 3,
            documents_count: 2,
        }
    }

    fn completed_envelope() -> EnvelopeStatusInfo {
        EnvelopeStatusInfo {
            envelope_id: "env-100".to_string(),
            status: "completed".to_string(),
            subject: Some("Contract final".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            sent_at: Some("2026-01-01T01:00:00Z".to_string()),
            completed_at: Some("2026-01-02T12:00:00Z".to_string()),
            voided_at: None,
            voided_reason: None,
            recipients_completed: 2,
            recipients_total: 2,
            documents_count: 1,
        }
    }

    fn voided_envelope() -> EnvelopeStatusInfo {
        EnvelopeStatusInfo {
            envelope_id: "env-200".to_string(),
            status: "voided".to_string(),
            subject: None,
            created_at: "2026-02-01T00:00:00Z".to_string(),
            sent_at: Some("2026-02-01T01:00:00Z".to_string()),
            completed_at: None,
            voided_at: Some("2026-02-02T08:00:00Z".to_string()),
            voided_reason: Some("Cancelled by sender".to_string()),
            recipients_completed: 0,
            recipients_total: 1,
            documents_count: 3,
        }
    }

    fn sample_recipient(status: RecipientStatusType) -> RecipientStatus {
        RecipientStatus {
            recipient_id: "r-001".to_string(),
            role: "signer".to_string(),
            status,
            routing_order: 1,
            signed_at: None,
            declined_at: None,
            delivered_at: None,
        }
    }

    // -----------------------------------------------------------------------
    // EnvelopeStatusInfo tests
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_status_progress_partial() {
        let info = sample_envelope_status();
        assert_eq!(info.progress_percent(), 33); // 1/3 * 100
    }

    #[test]
    fn envelope_status_progress_completed() {
        let info = completed_envelope();
        assert_eq!(info.progress_percent(), 100);
    }

    #[test]
    fn envelope_status_progress_voided() {
        let info = voided_envelope();
        assert_eq!(info.progress_percent(), 100);
    }

    #[test]
    fn envelope_status_progress_zero_recipients() {
        let mut info = sample_envelope_status();
        info.recipients_total = 0;
        info.recipients_completed = 0;
        info.status = "sent".to_string();
        assert_eq!(info.progress_percent(), 0);
    }

    #[test]
    fn envelope_status_progress_all_signed_but_not_completed() {
        let mut info = sample_envelope_status();
        info.recipients_completed = 3;
        assert_eq!(info.progress_percent(), 100);
    }

    #[test]
    fn envelope_status_progress_half() {
        let mut info = sample_envelope_status();
        info.recipients_completed = 1;
        info.recipients_total = 2;
        assert_eq!(info.progress_percent(), 50);
    }

    #[test]
    fn envelope_status_is_complete_true() {
        assert!(completed_envelope().is_complete());
    }

    #[test]
    fn envelope_status_is_complete_false_sent() {
        assert!(!sample_envelope_status().is_complete());
    }

    #[test]
    fn envelope_status_is_complete_false_voided() {
        assert!(!voided_envelope().is_complete());
    }

    #[test]
    fn envelope_status_is_voided_true() {
        assert!(voided_envelope().is_voided());
    }

    #[test]
    fn envelope_status_is_voided_false_sent() {
        assert!(!sample_envelope_status().is_voided());
    }

    #[test]
    fn envelope_status_is_voided_false_completed() {
        assert!(!completed_envelope().is_voided());
    }

    #[test]
    fn envelope_status_serde_roundtrip() {
        let info = sample_envelope_status();
        let json = serde_json::to_string(&info).unwrap();
        let back: EnvelopeStatusInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-001");
        assert_eq!(back.status, "sent");
        assert_eq!(back.recipients_completed, 1);
        assert_eq!(back.recipients_total, 3);
    }

    #[test]
    fn envelope_status_serde_with_nulls() {
        let info = EnvelopeStatusInfo {
            envelope_id: "e".to_string(),
            status: "created".to_string(),
            subject: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            sent_at: None,
            completed_at: None,
            voided_at: None,
            voided_reason: None,
            recipients_completed: 0,
            recipients_total: 0,
            documents_count: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"subject\":null"));
    }

    #[test]
    fn envelope_status_clone() {
        let info = sample_envelope_status();
        let cloned = info.clone();
        drop(info);
        assert_eq!(cloned.envelope_id, "env-001");
        assert_eq!(cloned.documents_count, 2);
    }

    #[test]
    fn envelope_status_debug() {
        let info = sample_envelope_status();
        let dbg = format!("{info:?}");
        assert!(dbg.contains("EnvelopeStatusInfo"));
        assert!(dbg.contains("env-001"));
    }

    #[test]
    fn envelope_status_voided_with_reason() {
        let info = voided_envelope();
        assert_eq!(info.voided_reason, Some("Cancelled by sender".to_string()));
        assert!(info.voided_at.is_some());
    }

    #[test]
    fn envelope_status_progress_capped_at_100() {
        let mut info = sample_envelope_status();
        info.recipients_completed = 5;
        info.recipients_total = 3;
        assert_eq!(info.progress_percent(), 100);
    }

    // -----------------------------------------------------------------------
    // RecipientStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn recipient_status_no_email_field() {
        // Verify RecipientStatus has no email/name fields by constructing one
        let r = sample_recipient(RecipientStatusType::Signed);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("email"));
        assert!(!json.contains("\"name\""));
    }

    #[test]
    fn recipient_status_serde_roundtrip() {
        let mut r = sample_recipient(RecipientStatusType::Delivered);
        r.delivered_at = Some("2026-01-15T11:00:00Z".to_string());
        let json = serde_json::to_string(&r).unwrap();
        let back: RecipientStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.recipient_id, "r-001");
        assert_eq!(back.status, RecipientStatusType::Delivered);
        assert_eq!(back.delivered_at, Some("2026-01-15T11:00:00Z".to_string()));
    }

    #[test]
    fn recipient_status_clone() {
        let r = sample_recipient(RecipientStatusType::Sent);
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.recipient_id, "r-001");
        assert_eq!(cloned.role, "signer");
    }

    #[test]
    fn recipient_status_debug() {
        let r = sample_recipient(RecipientStatusType::Created);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RecipientStatus"));
        assert!(dbg.contains("Created"));
    }

    #[test]
    fn recipient_status_with_signed_at() {
        let mut r = sample_recipient(RecipientStatusType::Signed);
        r.signed_at = Some("2026-01-16T14:00:00Z".to_string());
        assert!(r.signed_at.is_some());
        assert!(r.declined_at.is_none());
    }

    #[test]
    fn recipient_status_with_declined_at() {
        let mut r = sample_recipient(RecipientStatusType::Declined);
        r.declined_at = Some("2026-01-16T15:00:00Z".to_string());
        assert!(r.declined_at.is_some());
        assert!(r.signed_at.is_none());
    }

    // -----------------------------------------------------------------------
    // RecipientStatusType tests
    // -----------------------------------------------------------------------

    #[test]
    fn recipient_status_type_created_not_terminal() {
        assert!(!RecipientStatusType::Created.is_terminal());
    }

    #[test]
    fn recipient_status_type_sent_not_terminal() {
        assert!(!RecipientStatusType::Sent.is_terminal());
    }

    #[test]
    fn recipient_status_type_delivered_not_terminal() {
        assert!(!RecipientStatusType::Delivered.is_terminal());
    }

    #[test]
    fn recipient_status_type_signed_is_terminal() {
        assert!(RecipientStatusType::Signed.is_terminal());
    }

    #[test]
    fn recipient_status_type_declined_is_terminal() {
        assert!(RecipientStatusType::Declined.is_terminal());
    }

    #[test]
    fn recipient_status_type_auth_failed_is_terminal() {
        assert!(RecipientStatusType::AuthenticationFailed.is_terminal());
    }

    #[test]
    fn recipient_status_type_auto_responded_not_terminal() {
        assert!(!RecipientStatusType::AutoResponded.is_terminal());
    }

    #[test]
    fn recipient_status_type_signed_is_successful() {
        assert!(RecipientStatusType::Signed.is_successful());
    }

    #[test]
    fn recipient_status_type_declined_not_successful() {
        assert!(!RecipientStatusType::Declined.is_successful());
    }

    #[test]
    fn recipient_status_type_created_not_successful() {
        assert!(!RecipientStatusType::Created.is_successful());
    }

    #[test]
    fn recipient_status_type_auth_failed_not_successful() {
        assert!(!RecipientStatusType::AuthenticationFailed.is_successful());
    }

    #[test]
    fn recipient_status_type_as_str() {
        assert_eq!(RecipientStatusType::Created.as_str(), "created");
        assert_eq!(RecipientStatusType::Sent.as_str(), "sent");
        assert_eq!(RecipientStatusType::Delivered.as_str(), "delivered");
        assert_eq!(RecipientStatusType::Signed.as_str(), "signed");
        assert_eq!(RecipientStatusType::Declined.as_str(), "declined");
        assert_eq!(
            RecipientStatusType::AuthenticationFailed.as_str(),
            "authentication_failed"
        );
        assert_eq!(
            RecipientStatusType::AutoResponded.as_str(),
            "auto_responded"
        );
    }

    #[test]
    fn recipient_status_type_display() {
        assert_eq!(RecipientStatusType::Signed.to_string(), "signed");
        assert_eq!(RecipientStatusType::Declined.to_string(), "declined");
        assert_eq!(
            RecipientStatusType::AuthenticationFailed.to_string(),
            "authentication_failed"
        );
    }

    #[test]
    fn recipient_status_type_from_str_valid() {
        assert_eq!(
            "created".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::Created
        );
        assert_eq!(
            "sent".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::Sent
        );
        assert_eq!(
            "delivered".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::Delivered
        );
        assert_eq!(
            "signed".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::Signed
        );
        assert_eq!(
            "completed".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::Signed
        );
        assert_eq!(
            "declined".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::Declined
        );
    }

    #[test]
    fn recipient_status_type_from_str_auth_failed_variants() {
        assert_eq!(
            "authentication_failed"
                .parse::<RecipientStatusType>()
                .unwrap(),
            RecipientStatusType::AuthenticationFailed
        );
        assert_eq!(
            "authenticationfailed"
                .parse::<RecipientStatusType>()
                .unwrap(),
            RecipientStatusType::AuthenticationFailed
        );
    }

    #[test]
    fn recipient_status_type_from_str_auto_responded_variants() {
        assert_eq!(
            "auto_responded".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::AutoResponded
        );
        assert_eq!(
            "autoresponded".parse::<RecipientStatusType>().unwrap(),
            RecipientStatusType::AutoResponded
        );
    }

    #[test]
    fn recipient_status_type_from_str_invalid() {
        let err = "unknown_status".parse::<RecipientStatusType>().unwrap_err();
        assert_eq!(
            err,
            TrackingValidationError::InvalidStatus("unknown_status".to_string())
        );
    }

    #[test]
    fn recipient_status_type_from_str_empty() {
        assert!("".parse::<RecipientStatusType>().is_err());
    }

    #[test]
    fn recipient_status_type_eq() {
        assert_eq!(RecipientStatusType::Signed, RecipientStatusType::Signed);
        assert_ne!(RecipientStatusType::Signed, RecipientStatusType::Declined);
    }

    #[test]
    fn recipient_status_type_copy() {
        let s = RecipientStatusType::Delivered;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn recipient_status_type_serde_roundtrip() {
        let s = RecipientStatusType::AuthenticationFailed;
        let json = serde_json::to_string(&s).unwrap();
        let back: RecipientStatusType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, RecipientStatusType::AuthenticationFailed);
    }

    // -----------------------------------------------------------------------
    // EnvelopeListQuery tests
    // -----------------------------------------------------------------------

    #[test]
    fn query_default_values() {
        let q = EnvelopeListQuery::new();
        assert_eq!(q.limit, 25);
        assert_eq!(q.offset, 0);
        assert!(q.status_filter.is_none());
        assert!(q.from_date.is_none());
        assert!(q.to_date.is_none());
        assert!(q.search_text.is_none());
        assert!(q.folder_id.is_none());
    }

    #[test]
    fn query_with_status_single() {
        let q = EnvelopeListQuery::new().with_status("completed");
        assert_eq!(q.status_filter, Some(vec!["completed".to_string()]));
    }

    #[test]
    fn query_with_status_multiple() {
        let q = EnvelopeListQuery::new()
            .with_status("completed")
            .with_status("sent");
        assert_eq!(
            q.status_filter,
            Some(vec!["completed".to_string(), "sent".to_string()])
        );
    }

    #[test]
    fn query_with_date_range() {
        let q = EnvelopeListQuery::new().with_date_range("2026-01-01", "2026-02-01");
        assert_eq!(q.from_date, Some("2026-01-01".to_string()));
        assert_eq!(q.to_date, Some("2026-02-01".to_string()));
    }

    #[test]
    fn query_with_search() {
        let q = EnvelopeListQuery::new().with_search("NDA");
        assert_eq!(q.search_text, Some("NDA".to_string()));
    }

    #[test]
    fn query_with_limit() {
        let q = EnvelopeListQuery::new().with_limit(50);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn query_with_offset() {
        let q = EnvelopeListQuery::new().with_offset(10);
        assert_eq!(q.offset, 10);
    }

    #[test]
    fn query_with_folder() {
        let q = EnvelopeListQuery::new().with_folder("folder-123");
        assert_eq!(q.folder_id, Some("folder-123".to_string()));
    }

    #[test]
    fn query_builder_chain() {
        let q = EnvelopeListQuery::new()
            .with_status("sent")
            .with_date_range("2026-01-01", "2026-03-01")
            .with_search("contract")
            .with_limit(10)
            .with_offset(5)
            .with_folder("f-1");
        assert_eq!(q.status_filter, Some(vec!["sent".to_string()]));
        assert_eq!(q.from_date, Some("2026-01-01".to_string()));
        assert_eq!(q.search_text, Some("contract".to_string()));
        assert_eq!(q.limit, 10);
        assert_eq!(q.offset, 5);
        assert_eq!(q.folder_id, Some("f-1".to_string()));
    }

    #[test]
    fn query_validate_default_ok() {
        assert!(EnvelopeListQuery::new().validate().is_ok());
    }

    #[test]
    fn query_validate_limit_zero() {
        let q = EnvelopeListQuery::new().with_limit(0);
        assert_eq!(
            q.validate().unwrap_err(),
            TrackingValidationError::InvalidLimit(0)
        );
    }

    #[test]
    fn query_validate_limit_101() {
        let q = EnvelopeListQuery::new().with_limit(101);
        assert_eq!(
            q.validate().unwrap_err(),
            TrackingValidationError::InvalidLimit(101)
        );
    }

    #[test]
    fn query_validate_limit_100_ok() {
        let q = EnvelopeListQuery::new().with_limit(100);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_limit_1_ok() {
        let q = EnvelopeListQuery::new().with_limit(1);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_from_without_to() {
        let mut q = EnvelopeListQuery::new();
        q.from_date = Some("2026-01-01".to_string());
        let err = q.validate().unwrap_err();
        assert!(matches!(err, TrackingValidationError::InvalidDateRange(_)));
    }

    #[test]
    fn query_validate_to_without_from() {
        let mut q = EnvelopeListQuery::new();
        q.to_date = Some("2026-02-01".to_string());
        let err = q.validate().unwrap_err();
        assert!(matches!(err, TrackingValidationError::InvalidDateRange(_)));
    }

    #[test]
    fn query_validate_both_dates_ok() {
        let q = EnvelopeListQuery::new().with_date_range("2026-01-01", "2026-02-01");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_invalid_status() {
        let q = EnvelopeListQuery::new().with_status("bogus");
        assert_eq!(
            q.validate().unwrap_err(),
            TrackingValidationError::InvalidStatus("bogus".to_string())
        );
    }

    #[test]
    fn query_validate_valid_statuses() {
        for status in &[
            "created",
            "sent",
            "delivered",
            "completed",
            "declined",
            "voided",
        ] {
            let q = EnvelopeListQuery::new().with_status(status);
            assert!(q.validate().is_ok(), "status {status} should be valid");
        }
    }

    #[test]
    fn query_serde_roundtrip() {
        let q = EnvelopeListQuery::new().with_status("sent").with_limit(10);
        let json = serde_json::to_string(&q).unwrap();
        let back: EnvelopeListQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back.limit, 10);
        assert_eq!(back.status_filter, Some(vec!["sent".to_string()]));
    }

    #[test]
    fn query_clone() {
        let q = EnvelopeListQuery::new()
            .with_status("completed")
            .with_limit(50);
        let cloned = q.clone();
        drop(q);
        assert_eq!(cloned.limit, 50);
    }

    #[test]
    fn query_debug() {
        let q = EnvelopeListQuery::new();
        let dbg = format!("{q:?}");
        assert!(dbg.contains("EnvelopeListQuery"));
    }

    // -----------------------------------------------------------------------
    // EnvelopeListPage tests
    // -----------------------------------------------------------------------

    #[test]
    fn page_has_more_true() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status()],
            total_count: 50,
            result_set_size: 1,
            start_position: 0,
            end_position: 0,
        };
        assert!(page.has_more());
    }

    #[test]
    fn page_has_more_false() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status()],
            total_count: 1,
            result_set_size: 1,
            start_position: 0,
            end_position: 0,
        };
        assert!(!page.has_more());
    }

    #[test]
    fn page_has_more_last_page() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status(); 10],
            total_count: 20,
            result_set_size: 10,
            start_position: 10,
            end_position: 19,
        };
        assert!(!page.has_more());
    }

    #[test]
    fn page_is_empty_true() {
        let page = EnvelopeListPage {
            envelopes: vec![],
            total_count: 0,
            result_set_size: 0,
            start_position: 0,
            end_position: 0,
        };
        assert!(page.is_empty());
    }

    #[test]
    fn page_is_empty_false() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status()],
            total_count: 1,
            result_set_size: 1,
            start_position: 0,
            end_position: 0,
        };
        assert!(!page.is_empty());
    }

    #[test]
    fn page_serde_roundtrip() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status(), completed_envelope()],
            total_count: 100,
            result_set_size: 2,
            start_position: 0,
            end_position: 1,
        };
        let json = serde_json::to_string(&page).unwrap();
        let back: EnvelopeListPage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelopes.len(), 2);
        assert_eq!(back.total_count, 100);
    }

    #[test]
    fn page_clone() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status()],
            total_count: 1,
            result_set_size: 1,
            start_position: 0,
            end_position: 0,
        };
        let cloned = page.clone();
        drop(page);
        assert_eq!(cloned.total_count, 1);
    }

    #[test]
    fn page_debug() {
        let page = EnvelopeListPage {
            envelopes: vec![],
            total_count: 0,
            result_set_size: 0,
            start_position: 0,
            end_position: 0,
        };
        let dbg = format!("{page:?}");
        assert!(dbg.contains("EnvelopeListPage"));
    }

    // -----------------------------------------------------------------------
    // StatusWebhook tests
    // -----------------------------------------------------------------------

    #[test]
    fn webhook_validate_ok() {
        let wh = StatusWebhook {
            event_type: "envelope-sent".to_string(),
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert!(wh.validate().is_ok());
    }

    #[test]
    fn webhook_validate_empty_envelope_id() {
        let wh = StatusWebhook {
            event_type: "envelope-sent".to_string(),
            envelope_id: String::new(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert_eq!(
            wh.validate().unwrap_err(),
            TrackingValidationError::EmptyEnvelopeId
        );
    }

    #[test]
    fn webhook_validate_unknown_event_type() {
        let wh = StatusWebhook {
            event_type: "unknown-event".to_string(),
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert_eq!(
            wh.validate().unwrap_err(),
            TrackingValidationError::UnknownWebhookEvent("unknown-event".to_string())
        );
    }

    #[test]
    fn webhook_validate_all_known_event_types() {
        for evt in WebhookEventType::all() {
            let wh = StatusWebhook {
                event_type: evt.as_str().to_string(),
                envelope_id: "env-001".to_string(),
                status: "sent".to_string(),
                timestamp: "2026-01-15T10:00:00Z".to_string(),
                recipient_statuses: vec![],
            };
            assert!(
                wh.validate().is_ok(),
                "event type {} should be valid",
                evt.as_str()
            );
        }
    }

    #[test]
    fn webhook_with_recipient_statuses() {
        let wh = StatusWebhook {
            event_type: "recipient-signed".to_string(),
            envelope_id: "env-001".to_string(),
            status: "signed".to_string(),
            timestamp: "2026-01-15T12:00:00Z".to_string(),
            recipient_statuses: vec![
                sample_recipient(RecipientStatusType::Signed),
                sample_recipient(RecipientStatusType::Delivered),
            ],
        };
        assert!(wh.validate().is_ok());
        assert_eq!(wh.recipient_statuses.len(), 2);
    }

    #[test]
    fn webhook_serde_roundtrip() {
        let wh = StatusWebhook {
            event_type: "envelope-completed".to_string(),
            envelope_id: "env-999".to_string(),
            status: "completed".to_string(),
            timestamp: "2026-03-01T00:00:00Z".to_string(),
            recipient_statuses: vec![sample_recipient(RecipientStatusType::Signed)],
        };
        let json = serde_json::to_string(&wh).unwrap();
        let back: StatusWebhook = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, "env-999");
        assert_eq!(back.recipient_statuses.len(), 1);
    }

    #[test]
    fn webhook_clone() {
        let wh = StatusWebhook {
            event_type: "envelope-sent".to_string(),
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        let cloned = wh.clone();
        drop(wh);
        assert_eq!(cloned.envelope_id, "env-001");
    }

    #[test]
    fn webhook_debug() {
        let wh = StatusWebhook {
            event_type: "envelope-sent".to_string(),
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        let dbg = format!("{wh:?}");
        assert!(dbg.contains("StatusWebhook"));
    }

    // -----------------------------------------------------------------------
    // WebhookEventType tests
    // -----------------------------------------------------------------------

    #[test]
    fn webhook_event_type_as_str() {
        assert_eq!(WebhookEventType::EnvelopeSent.as_str(), "envelope-sent");
        assert_eq!(
            WebhookEventType::EnvelopeDelivered.as_str(),
            "envelope-delivered"
        );
        assert_eq!(
            WebhookEventType::EnvelopeCompleted.as_str(),
            "envelope-completed"
        );
        assert_eq!(
            WebhookEventType::EnvelopeDeclined.as_str(),
            "envelope-declined"
        );
        assert_eq!(WebhookEventType::EnvelopeVoided.as_str(), "envelope-voided");
        assert_eq!(
            WebhookEventType::RecipientSigned.as_str(),
            "recipient-signed"
        );
        assert_eq!(
            WebhookEventType::RecipientDeclined.as_str(),
            "recipient-declined"
        );
        assert_eq!(
            WebhookEventType::RecipientDelivered.as_str(),
            "recipient-delivered"
        );
    }

    #[test]
    fn webhook_event_type_display() {
        assert_eq!(WebhookEventType::EnvelopeSent.to_string(), "envelope-sent");
        assert_eq!(
            WebhookEventType::RecipientSigned.to_string(),
            "recipient-signed"
        );
    }

    #[test]
    fn webhook_event_type_from_str_all_variants() {
        assert_eq!(
            "envelope-sent".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::EnvelopeSent
        );
        assert_eq!(
            "envelope-delivered".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::EnvelopeDelivered
        );
        assert_eq!(
            "envelope-completed".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::EnvelopeCompleted
        );
        assert_eq!(
            "envelope-declined".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::EnvelopeDeclined
        );
        assert_eq!(
            "envelope-voided".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::EnvelopeVoided
        );
        assert_eq!(
            "recipient-signed".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::RecipientSigned
        );
        assert_eq!(
            "recipient-declined".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::RecipientDeclined
        );
        assert_eq!(
            "recipient-delivered".parse::<WebhookEventType>().unwrap(),
            WebhookEventType::RecipientDelivered
        );
    }

    #[test]
    fn webhook_event_type_from_str_invalid() {
        let err = "bogus-event".parse::<WebhookEventType>().unwrap_err();
        assert_eq!(
            err,
            TrackingValidationError::UnknownWebhookEvent("bogus-event".to_string())
        );
    }

    #[test]
    fn webhook_event_type_is_envelope_event() {
        assert!(WebhookEventType::EnvelopeSent.is_envelope_event());
        assert!(WebhookEventType::EnvelopeDelivered.is_envelope_event());
        assert!(WebhookEventType::EnvelopeCompleted.is_envelope_event());
        assert!(WebhookEventType::EnvelopeDeclined.is_envelope_event());
        assert!(WebhookEventType::EnvelopeVoided.is_envelope_event());
        assert!(!WebhookEventType::RecipientSigned.is_envelope_event());
        assert!(!WebhookEventType::RecipientDeclined.is_envelope_event());
        assert!(!WebhookEventType::RecipientDelivered.is_envelope_event());
    }

    #[test]
    fn webhook_event_type_is_recipient_event() {
        assert!(!WebhookEventType::EnvelopeSent.is_recipient_event());
        assert!(!WebhookEventType::EnvelopeCompleted.is_recipient_event());
        assert!(WebhookEventType::RecipientSigned.is_recipient_event());
        assert!(WebhookEventType::RecipientDeclined.is_recipient_event());
        assert!(WebhookEventType::RecipientDelivered.is_recipient_event());
    }

    #[test]
    fn webhook_event_type_is_terminal() {
        assert!(!WebhookEventType::EnvelopeSent.is_terminal());
        assert!(!WebhookEventType::EnvelopeDelivered.is_terminal());
        assert!(WebhookEventType::EnvelopeCompleted.is_terminal());
        assert!(WebhookEventType::EnvelopeDeclined.is_terminal());
        assert!(WebhookEventType::EnvelopeVoided.is_terminal());
        assert!(!WebhookEventType::RecipientSigned.is_terminal());
        assert!(!WebhookEventType::RecipientDeclined.is_terminal());
        assert!(!WebhookEventType::RecipientDelivered.is_terminal());
    }

    #[test]
    fn webhook_event_type_all_count() {
        assert_eq!(WebhookEventType::all().len(), 8);
    }

    #[test]
    fn webhook_event_type_eq() {
        assert_eq!(
            WebhookEventType::EnvelopeSent,
            WebhookEventType::EnvelopeSent
        );
        assert_ne!(
            WebhookEventType::EnvelopeSent,
            WebhookEventType::EnvelopeVoided
        );
    }

    #[test]
    fn webhook_event_type_copy() {
        let e = WebhookEventType::RecipientSigned;
        let copied = e;
        assert_eq!(e, copied);
    }

    #[test]
    fn webhook_event_type_serde_roundtrip() {
        let e = WebhookEventType::EnvelopeVoided;
        let json = serde_json::to_string(&e).unwrap();
        let back: WebhookEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, WebhookEventType::EnvelopeVoided);
    }

    // -----------------------------------------------------------------------
    // TrackingValidator tests
    // -----------------------------------------------------------------------

    #[test]
    fn validator_default() {
        let v = TrackingValidator::default();
        assert_eq!(v.max_limit, 100);
        assert_eq!(v.max_date_range_days, 365);
        assert!(!v.allowed_statuses.is_empty());
    }

    #[test]
    fn validator_default_allowed_statuses() {
        let statuses = TrackingValidator::default_allowed_statuses();
        assert!(statuses.contains(&"created"));
        assert!(statuses.contains(&"sent"));
        assert!(statuses.contains(&"completed"));
        assert!(statuses.contains(&"voided"));
        assert!(statuses.contains(&"declined"));
        assert!(statuses.contains(&"any"));
    }

    #[test]
    fn validator_validate_query_ok() {
        let v = TrackingValidator::default();
        let q = EnvelopeListQuery::new();
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_validate_query_limit_zero() {
        let v = TrackingValidator::default();
        let q = EnvelopeListQuery::new().with_limit(0);
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            TrackingValidationError::InvalidLimit(0)
        );
    }

    #[test]
    fn validator_validate_query_limit_over_max() {
        let v = TrackingValidator::default();
        let q = EnvelopeListQuery::new().with_limit(101);
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            TrackingValidationError::InvalidLimit(101)
        );
    }

    #[test]
    fn validator_validate_query_custom_max_limit() {
        let v = TrackingValidator {
            max_limit: 50,
            ..Default::default()
        };
        let q = EnvelopeListQuery::new().with_limit(51);
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            TrackingValidationError::InvalidLimit(51)
        );
        let q2 = EnvelopeListQuery::new().with_limit(50);
        assert!(v.validate_query(&q2).is_ok());
    }

    #[test]
    fn validator_validate_query_missing_to_date() {
        let v = TrackingValidator::default();
        let mut q = EnvelopeListQuery::new();
        q.from_date = Some("2026-01-01".to_string());
        let err = v.validate_query(&q).unwrap_err();
        assert!(matches!(err, TrackingValidationError::InvalidDateRange(_)));
    }

    #[test]
    fn validator_validate_query_missing_from_date() {
        let v = TrackingValidator::default();
        let mut q = EnvelopeListQuery::new();
        q.to_date = Some("2026-02-01".to_string());
        let err = v.validate_query(&q).unwrap_err();
        assert!(matches!(err, TrackingValidationError::InvalidDateRange(_)));
    }

    #[test]
    fn validator_validate_query_invalid_status() {
        let v = TrackingValidator::default();
        let q = EnvelopeListQuery::new().with_status("invalid_status");
        assert_eq!(
            v.validate_query(&q).unwrap_err(),
            TrackingValidationError::InvalidStatus("invalid_status".to_string())
        );
    }

    #[test]
    fn validator_validate_query_valid_status() {
        let v = TrackingValidator::default();
        let q = EnvelopeListQuery::new()
            .with_status("completed")
            .with_status("sent");
        assert!(v.validate_query(&q).is_ok());
    }

    #[test]
    fn validator_validate_webhook_ok() {
        let v = TrackingValidator::default();
        let wh = StatusWebhook {
            event_type: "envelope-sent".to_string(),
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert!(v.validate_webhook(&wh).is_ok());
    }

    #[test]
    fn validator_validate_webhook_empty_id() {
        let v = TrackingValidator::default();
        let wh = StatusWebhook {
            event_type: "envelope-sent".to_string(),
            envelope_id: String::new(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert_eq!(
            v.validate_webhook(&wh).unwrap_err(),
            TrackingValidationError::EmptyEnvelopeId
        );
    }

    #[test]
    fn validator_validate_webhook_unknown_event() {
        let v = TrackingValidator::default();
        let wh = StatusWebhook {
            event_type: "foo-bar".to_string(),
            envelope_id: "env-001".to_string(),
            status: "sent".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert_eq!(
            v.validate_webhook(&wh).unwrap_err(),
            TrackingValidationError::UnknownWebhookEvent("foo-bar".to_string())
        );
    }

    #[test]
    fn validator_serde_roundtrip() {
        let v = TrackingValidator::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: TrackingValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_limit, 100);
        assert_eq!(back.max_date_range_days, 365);
    }

    #[test]
    fn validator_clone() {
        let v = TrackingValidator::default();
        let cloned = v.clone();
        drop(v);
        assert_eq!(cloned.max_limit, 100);
    }

    #[test]
    fn validator_debug() {
        let v = TrackingValidator::default();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("TrackingValidator"));
    }

    // -----------------------------------------------------------------------
    // TrackingValidationError tests
    // -----------------------------------------------------------------------

    #[test]
    fn validation_error_display_invalid_limit() {
        let err = TrackingValidationError::InvalidLimit(200);
        assert_eq!(
            err.to_string(),
            "invalid limit: 200 (must be between 1 and 100)"
        );
    }

    #[test]
    fn validation_error_display_invalid_date_range() {
        let err = TrackingValidationError::InvalidDateRange("dates out of order".to_string());
        assert_eq!(err.to_string(), "invalid date range: dates out of order");
    }

    #[test]
    fn validation_error_display_invalid_status() {
        let err = TrackingValidationError::InvalidStatus("bogus".to_string());
        assert_eq!(err.to_string(), "invalid status: bogus");
    }

    #[test]
    fn validation_error_display_empty_envelope_id() {
        let err = TrackingValidationError::EmptyEnvelopeId;
        assert_eq!(err.to_string(), "envelope ID must not be empty");
    }

    #[test]
    fn validation_error_display_unknown_webhook_event() {
        let err = TrackingValidationError::UnknownWebhookEvent("foo".to_string());
        assert_eq!(err.to_string(), "unknown webhook event: foo");
    }

    #[test]
    fn validation_error_eq() {
        assert_eq!(
            TrackingValidationError::EmptyEnvelopeId,
            TrackingValidationError::EmptyEnvelopeId
        );
        assert_ne!(
            TrackingValidationError::EmptyEnvelopeId,
            TrackingValidationError::InvalidLimit(0)
        );
    }

    #[test]
    fn validation_error_clone() {
        let err = TrackingValidationError::InvalidLimit(42);
        let cloned = err.clone();
        drop(err);
        assert_eq!(cloned, TrackingValidationError::InvalidLimit(42));
    }

    #[test]
    fn validation_error_debug() {
        let err = TrackingValidationError::InvalidLimit(0);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidLimit"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let err = TrackingValidationError::UnknownWebhookEvent("x".to_string());
        let json = serde_json::to_string(&err).unwrap();
        let back: TrackingValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }

    #[test]
    fn validation_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TrackingValidationError::EmptyEnvelopeId);
        assert!(err.to_string().contains("envelope ID"));
    }

    // -----------------------------------------------------------------------
    // TrackingAction tests
    // -----------------------------------------------------------------------

    #[test]
    fn tracking_action_display_query() {
        assert_eq!(TrackingAction::Query.to_string(), "query");
    }

    #[test]
    fn tracking_action_display_webhook_received() {
        assert_eq!(
            TrackingAction::WebhookReceived.to_string(),
            "webhook_received"
        );
    }

    #[test]
    fn tracking_action_eq() {
        assert_eq!(TrackingAction::Query, TrackingAction::Query);
        assert_ne!(TrackingAction::Query, TrackingAction::WebhookReceived);
    }

    #[test]
    fn tracking_action_copy() {
        let a = TrackingAction::Query;
        let copied = a;
        assert_eq!(a, copied);
    }

    #[test]
    fn tracking_action_serde_roundtrip() {
        let a = TrackingAction::WebhookReceived;
        let json = serde_json::to_string(&a).unwrap();
        let back: TrackingAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TrackingAction::WebhookReceived);
    }

    // -----------------------------------------------------------------------
    // TrackingAuditEvent tests
    // -----------------------------------------------------------------------

    #[test]
    fn audit_event_for_query() {
        let evt = TrackingAuditEvent::for_query("2026-01-15T10:00:00Z", 5, true);
        assert_eq!(evt.action, TrackingAction::Query);
        assert_eq!(evt.envelope_count, 5);
        assert!(evt.filter_used);
        assert_eq!(evt.timestamp, "2026-01-15T10:00:00Z");
    }

    #[test]
    fn audit_event_for_query_no_filter() {
        let evt = TrackingAuditEvent::for_query("2026-01-15T10:00:00Z", 0, false);
        assert!(!evt.filter_used);
        assert_eq!(evt.envelope_count, 0);
    }

    #[test]
    fn audit_event_for_webhook() {
        let evt = TrackingAuditEvent::for_webhook("2026-01-15T12:00:00Z");
        assert_eq!(evt.action, TrackingAction::WebhookReceived);
        assert_eq!(evt.envelope_count, 1);
        assert!(!evt.filter_used);
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = TrackingAuditEvent::for_query("2026-01-15T10:00:00Z", 10, true);
        let json = serde_json::to_string(&evt).unwrap();
        let back: TrackingAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_count, 10);
        assert!(back.filter_used);
    }

    #[test]
    fn audit_event_clone() {
        let evt = TrackingAuditEvent::for_webhook("2026-01-15T12:00:00Z");
        let cloned = evt.clone();
        drop(evt);
        assert_eq!(cloned.action, TrackingAction::WebhookReceived);
    }

    #[test]
    fn audit_event_debug() {
        let evt = TrackingAuditEvent::for_query("t", 0, false);
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("TrackingAuditEvent"));
    }

    // -----------------------------------------------------------------------
    // Privacy tests — ensure RecipientStatus doesn't leak PII
    // -----------------------------------------------------------------------

    #[test]
    fn recipient_status_json_has_no_email_key() {
        let r = RecipientStatus {
            recipient_id: "r-999".to_string(),
            role: "signer".to_string(),
            status: RecipientStatusType::Signed,
            routing_order: 1,
            signed_at: Some("2026-01-16T14:00:00Z".to_string()),
            declined_at: None,
            delivered_at: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("email"), "JSON must not contain email field");
        assert!(
            !json.contains("\"name\""),
            "JSON must not contain name field"
        );
    }

    #[test]
    fn recipient_status_json_contains_expected_fields() {
        let r = RecipientStatus {
            recipient_id: "r-123".to_string(),
            role: "carbon_copy".to_string(),
            status: RecipientStatusType::Delivered,
            routing_order: 2,
            signed_at: None,
            declined_at: None,
            delivered_at: Some("2026-03-01T09:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("recipient_id"));
        assert!(json.contains("role"));
        assert!(json.contains("status"));
        assert!(json.contains("routing_order"));
    }

    // -----------------------------------------------------------------------
    // Edge case / integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_status_declined() {
        let info = EnvelopeStatusInfo {
            envelope_id: "env-dec".to_string(),
            status: "declined".to_string(),
            subject: Some("Declined contract".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            sent_at: Some("2026-01-01T01:00:00Z".to_string()),
            completed_at: None,
            voided_at: None,
            voided_reason: None,
            recipients_completed: 0,
            recipients_total: 1,
            documents_count: 1,
        };
        assert!(!info.is_complete());
        assert!(!info.is_voided());
        assert_eq!(info.progress_percent(), 0);
    }

    #[test]
    fn envelope_status_created_no_progress() {
        let info = EnvelopeStatusInfo {
            envelope_id: "env-new".to_string(),
            status: "created".to_string(),
            subject: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            sent_at: None,
            completed_at: None,
            voided_at: None,
            voided_reason: None,
            recipients_completed: 0,
            recipients_total: 5,
            documents_count: 2,
        };
        assert_eq!(info.progress_percent(), 0);
        assert!(!info.is_complete());
    }

    #[test]
    fn query_validate_status_any() {
        let q = EnvelopeListQuery::new().with_status("any");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_status_deleted() {
        let q = EnvelopeListQuery::new().with_status("deleted");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn query_validate_status_template() {
        let q = EnvelopeListQuery::new().with_status("template");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn webhook_event_type_from_str_empty() {
        assert!("".parse::<WebhookEventType>().is_err());
    }

    #[test]
    fn page_single_item_no_more() {
        let page = EnvelopeListPage {
            envelopes: vec![sample_envelope_status()],
            total_count: 1,
            result_set_size: 1,
            start_position: 0,
            end_position: 0,
        };
        assert!(!page.has_more());
        assert!(!page.is_empty());
    }

    #[test]
    fn validator_custom_allowed_statuses() {
        let v = TrackingValidator {
            max_limit: 100,
            max_date_range_days: 365,
            allowed_statuses: vec!["sent".to_string(), "completed".to_string()],
        };
        let q = EnvelopeListQuery::new().with_status("sent");
        assert!(v.validate_query(&q).is_ok());
        let q2 = EnvelopeListQuery::new().with_status("voided");
        assert_eq!(
            v.validate_query(&q2).unwrap_err(),
            TrackingValidationError::InvalidStatus("voided".to_string())
        );
    }

    #[test]
    fn envelope_status_progress_one_of_one() {
        let mut info = sample_envelope_status();
        info.recipients_completed = 1;
        info.recipients_total = 1;
        info.status = "delivered".to_string();
        assert_eq!(info.progress_percent(), 100);
    }

    #[test]
    fn envelope_status_progress_two_of_five() {
        let mut info = sample_envelope_status();
        info.recipients_completed = 2;
        info.recipients_total = 5;
        assert_eq!(info.progress_percent(), 40);
    }

    #[test]
    fn recipient_all_optional_timestamps_none() {
        let r = sample_recipient(RecipientStatusType::Created);
        assert!(r.signed_at.is_none());
        assert!(r.declined_at.is_none());
        assert!(r.delivered_at.is_none());
    }

    #[test]
    fn recipient_high_routing_order() {
        let r = RecipientStatus {
            recipient_id: "r-100".to_string(),
            role: "in_person_signer".to_string(),
            status: RecipientStatusType::Sent,
            routing_order: 999,
            signed_at: None,
            declined_at: None,
            delivered_at: None,
        };
        assert_eq!(r.routing_order, 999);
    }

    #[test]
    fn webhook_empty_recipient_statuses_valid() {
        let wh = StatusWebhook {
            event_type: "envelope-voided".to_string(),
            envelope_id: "env-v".to_string(),
            status: "voided".to_string(),
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            recipient_statuses: vec![],
        };
        assert!(wh.validate().is_ok());
    }

    #[test]
    fn webhook_event_type_roundtrip_all() {
        for evt in WebhookEventType::all() {
            let s = evt.as_str();
            let parsed: WebhookEventType = s.parse().unwrap();
            assert_eq!(*evt, parsed);
        }
    }

    #[test]
    fn query_default_equals_new() {
        let d = EnvelopeListQuery::default();
        let n = EnvelopeListQuery::new();
        assert_eq!(d.limit, n.limit);
        assert_eq!(d.offset, n.offset);
    }

    #[test]
    fn validation_error_source_is_none() {
        let err = TrackingValidationError::EmptyEnvelopeId;
        assert!(std::error::Error::source(&err).is_none());
    }
}
