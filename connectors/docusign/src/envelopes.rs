//! `DocuSign` envelope creation and document management.
//!
//! Provides typed envelope/document models with validation, a builder
//! pattern for creating envelopes in draft state, and audit events for
//! the envelope lifecycle.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────

/// Default maximum document upload size (25 MB).
const DEFAULT_MAX_DOCUMENT_SIZE: u64 = 25 * 1024 * 1024;

/// Default maximum number of documents per envelope.
const DEFAULT_MAX_DOCUMENTS: usize = 10;

/// Default maximum number of recipients per envelope.
const DEFAULT_MAX_RECIPIENTS: usize = 20;

/// Default maximum subject length.
const DEFAULT_MAX_SUBJECT_LENGTH: usize = 100;

// ── EnvelopeStatus ───────────────────────────────────────────────────

/// Status of a `DocuSign` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvelopeStatus {
    /// Envelope has been created but not yet sent.
    Created,
    /// Envelope has been sent to recipients.
    Sent,
    /// Envelope has been delivered to at least one recipient.
    Delivered,
    /// All recipients have signed.
    Signed,
    /// Envelope processing is complete.
    Completed,
    /// A recipient declined to sign.
    Declined,
    /// Envelope was voided by the sender.
    Voided,
    /// Envelope is in draft state (not yet created on server).
    Draft,
}

impl EnvelopeStatus {
    /// Returns the string representation of the status.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Signed => "signed",
            Self::Completed => "completed",
            Self::Declined => "declined",
            Self::Voided => "voided",
            Self::Draft => "draft",
        }
    }

    /// Returns `true` if the envelope has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Declined | Self::Voided)
    }

    /// Returns `true` if the envelope is in an active (non-terminal) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.is_terminal()
    }
}

impl fmt::Display for EnvelopeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Document ─────────────────────────────────────────────────────────

/// A document to attach to an envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// Unique identifier for this document within the envelope.
    pub document_id: String,
    /// Display name for the document.
    pub name: String,
    /// File extension (e.g. "pdf", "docx").
    pub file_extension: String,
    /// MIME content type.
    pub content_type: String,
    /// Size in bytes (known after upload).
    pub size_bytes: Option<u64>,
    /// Display ordering within the envelope.
    pub order: u32,
}

impl Document {
    /// Validates the document against basic constraints.
    ///
    /// Checks that the name is non-empty, the file extension is in the
    /// allowlist, and the size (if known) is within limits.
    pub fn validate(&self, config: &EnvelopeConfig) -> Result<(), EnvelopeValidationError> {
        if self.name.is_empty() {
            return Err(EnvelopeValidationError::InvalidContentType {
                name: String::new(),
                content_type: self.content_type.clone(),
            });
        }
        if !config.allowed_content_types.contains(&self.file_extension) {
            return Err(EnvelopeValidationError::InvalidContentType {
                name: self.name.clone(),
                content_type: self.file_extension.clone(),
            });
        }
        if let Some(size) = self.size_bytes {
            if size > config.max_document_size_bytes {
                return Err(EnvelopeValidationError::DocumentTooLarge {
                    name: self.name.clone(),
                    max: config.max_document_size_bytes,
                    actual: size,
                });
            }
        }
        Ok(())
    }
}

// ── Recipients ───────────────────────────────────────────────────────

/// A signer recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    /// Email address.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Unique recipient identifier.
    pub recipient_id: String,
    /// Routing order (lower = earlier).
    pub routing_order: u32,
    /// Optional signing tabs (position/type metadata).
    pub tabs: Option<serde_json::Value>,
}

/// A CC (carbon copy) recipient — receives a copy but does not sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcRecipient {
    /// Email address.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Unique recipient identifier.
    pub recipient_id: String,
    /// Routing order.
    pub routing_order: u32,
}

/// A carbon copy recipient (alternative representation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarbonCopy {
    /// Email address.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Unique recipient identifier.
    pub recipient_id: String,
    /// Routing order.
    pub routing_order: u32,
}

/// Collection of recipients on an envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipients {
    /// Signers who must sign the documents.
    pub signers: Vec<Signer>,
    /// CC recipients who receive copies.
    pub cc_recipients: Vec<CcRecipient>,
    /// Carbon copy recipients (alternative list).
    pub carbon_copies: Vec<CarbonCopy>,
}

// ── Envelope ─────────────────────────────────────────────────────────

/// A `DocuSign` envelope with typed fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Server-assigned envelope ID (absent until created on server).
    pub envelope_id: Option<String>,
    /// Current status.
    pub status: EnvelopeStatus,
    /// Subject line for the signing request email.
    pub email_subject: String,
    /// Optional body text for the email.
    pub email_body: Option<String>,
    /// Documents attached to this envelope.
    pub documents: Vec<Document>,
    /// Recipients (if set).
    pub recipients: Option<Recipients>,
    /// Server-assigned creation timestamp.
    pub created_at: Option<String>,
    /// Server-assigned last-update timestamp.
    pub updated_at: Option<String>,
}

// ── EnvelopeConfig ───────────────────────────────────────────────────

/// Configuration/limits for envelope creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeConfig {
    /// Maximum document size in bytes.
    pub max_document_size_bytes: u64,
    /// Maximum number of documents per envelope.
    pub max_documents: usize,
    /// Allowed file extensions for documents.
    pub allowed_content_types: HashSet<String>,
    /// Maximum number of recipients (signers + CC).
    pub max_recipients: usize,
    /// Maximum subject line length.
    pub max_subject_length: usize,
}

impl Default for EnvelopeConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        for ext in &["pdf", "docx", "doc", "png", "jpg"] {
            allowed.insert((*ext).to_string());
        }
        Self {
            max_document_size_bytes: DEFAULT_MAX_DOCUMENT_SIZE,
            max_documents: DEFAULT_MAX_DOCUMENTS,
            allowed_content_types: allowed,
            max_recipients: DEFAULT_MAX_RECIPIENTS,
            max_subject_length: DEFAULT_MAX_SUBJECT_LENGTH,
        }
    }
}

impl EnvelopeConfig {
    /// Validates a single document against this configuration.
    pub fn validate_document(&self, doc: &Document) -> Result<(), EnvelopeValidationError> {
        doc.validate(self)
    }

    /// Validates an entire envelope against this configuration.
    pub fn validate_envelope(&self, envelope: &Envelope) -> Result<(), EnvelopeValidationError> {
        if envelope.email_subject.is_empty() {
            return Err(EnvelopeValidationError::EmptySubject);
        }
        if envelope.email_subject.len() > self.max_subject_length {
            return Err(EnvelopeValidationError::SubjectTooLong {
                max: self.max_subject_length,
                actual: envelope.email_subject.len(),
            });
        }
        if envelope.documents.is_empty() {
            return Err(EnvelopeValidationError::NoDocuments);
        }
        if envelope.documents.len() > self.max_documents {
            return Err(EnvelopeValidationError::TooManyDocuments {
                max: self.max_documents,
                actual: envelope.documents.len(),
            });
        }
        for doc in &envelope.documents {
            doc.validate(self)?;
        }
        if let Some(ref recips) = envelope.recipients {
            let total = recips.signers.len()
                + recips.cc_recipients.len()
                + recips.carbon_copies.len();
            if total > self.max_recipients {
                return Err(EnvelopeValidationError::TooManyRecipients {
                    max: self.max_recipients,
                    actual: total,
                });
            }
            // Check for duplicate recipient IDs.
            let mut seen = HashSet::new();
            for s in &recips.signers {
                if !seen.insert(&s.recipient_id) {
                    return Err(EnvelopeValidationError::DuplicateRecipientId {
                        recipient_id: s.recipient_id.clone(),
                    });
                }
                if !is_valid_email(&s.email) {
                    return Err(EnvelopeValidationError::InvalidEmail {
                        email: s.email.clone(),
                    });
                }
            }
            for cc in &recips.cc_recipients {
                if !seen.insert(&cc.recipient_id) {
                    return Err(EnvelopeValidationError::DuplicateRecipientId {
                        recipient_id: cc.recipient_id.clone(),
                    });
                }
                if !is_valid_email(&cc.email) {
                    return Err(EnvelopeValidationError::InvalidEmail {
                        email: cc.email.clone(),
                    });
                }
            }
            for cc in &recips.carbon_copies {
                if !seen.insert(&cc.recipient_id) {
                    return Err(EnvelopeValidationError::DuplicateRecipientId {
                        recipient_id: cc.recipient_id.clone(),
                    });
                }
                if !is_valid_email(&cc.email) {
                    return Err(EnvelopeValidationError::InvalidEmail {
                        email: cc.email.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Simple email validation — requires `@` with non-empty local and domain.
fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
}

// ── EnvelopeBuilder ──────────────────────────────────────────────────

/// Builder for constructing envelopes with validation.
#[derive(Debug, Clone)]
pub struct EnvelopeBuilder {
    subject: String,
    body: Option<String>,
    documents: Vec<Document>,
    signers: Vec<Signer>,
    cc_recipients: Vec<CcRecipient>,
    config: EnvelopeConfig,
}

impl EnvelopeBuilder {
    /// Creates a new builder with the given email subject.
    #[must_use]
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            body: None,
            documents: Vec::new(),
            signers: Vec::new(),
            cc_recipients: Vec::new(),
            config: EnvelopeConfig::default(),
        }
    }

    /// Sets the email body text.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets a custom envelope configuration for validation.
    #[must_use]
    pub fn with_config(mut self, config: EnvelopeConfig) -> Self {
        self.config = config;
        self
    }

    /// Adds a document to the envelope.
    #[must_use]
    pub fn add_document(mut self, doc: Document) -> Self {
        self.documents.push(doc);
        self
    }

    /// Adds a signer recipient.
    #[must_use]
    pub fn add_signer(mut self, signer: Signer) -> Self {
        self.signers.push(signer);
        self
    }

    /// Adds a CC recipient.
    #[must_use]
    pub fn add_cc(mut self, cc: CcRecipient) -> Self {
        self.cc_recipients.push(cc);
        self
    }

    /// Builds the envelope, validating against the configuration.
    pub fn build(self) -> Result<Envelope, EnvelopeValidationError> {
        if self.subject.is_empty() {
            return Err(EnvelopeValidationError::EmptySubject);
        }
        if self.subject.len() > self.config.max_subject_length {
            return Err(EnvelopeValidationError::SubjectTooLong {
                max: self.config.max_subject_length,
                actual: self.subject.len(),
            });
        }
        if self.documents.is_empty() {
            return Err(EnvelopeValidationError::NoDocuments);
        }
        if self.documents.len() > self.config.max_documents {
            return Err(EnvelopeValidationError::TooManyDocuments {
                max: self.config.max_documents,
                actual: self.documents.len(),
            });
        }
        for doc in &self.documents {
            doc.validate(&self.config)?;
        }
        if self.signers.is_empty() && self.cc_recipients.is_empty() {
            return Err(EnvelopeValidationError::NoRecipients);
        }
        let total = self.signers.len() + self.cc_recipients.len();
        if total > self.config.max_recipients {
            return Err(EnvelopeValidationError::TooManyRecipients {
                max: self.config.max_recipients,
                actual: total,
            });
        }
        // Check duplicate recipient IDs.
        let mut seen = HashSet::new();
        for s in &self.signers {
            if !seen.insert(&s.recipient_id) {
                return Err(EnvelopeValidationError::DuplicateRecipientId {
                    recipient_id: s.recipient_id.clone(),
                });
            }
            if !is_valid_email(&s.email) {
                return Err(EnvelopeValidationError::InvalidEmail {
                    email: s.email.clone(),
                });
            }
        }
        for cc in &self.cc_recipients {
            if !seen.insert(&cc.recipient_id) {
                return Err(EnvelopeValidationError::DuplicateRecipientId {
                    recipient_id: cc.recipient_id.clone(),
                });
            }
            if !is_valid_email(&cc.email) {
                return Err(EnvelopeValidationError::InvalidEmail {
                    email: cc.email.clone(),
                });
            }
        }

        Ok(Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: self.subject,
            email_body: self.body,
            documents: self.documents,
            recipients: Some(Recipients {
                signers: self.signers,
                cc_recipients: self.cc_recipients,
                carbon_copies: Vec::new(),
            }),
            created_at: None,
            updated_at: None,
        })
    }
}

// ── Validation errors ────────────────────────────────────────────────

/// Validation errors for envelope creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeValidationError {
    /// Subject line is empty.
    EmptySubject,
    /// Subject line exceeds the maximum length.
    SubjectTooLong { max: usize, actual: usize },
    /// No documents attached.
    NoDocuments,
    /// Too many documents attached.
    TooManyDocuments { max: usize, actual: usize },
    /// A document exceeds the size limit.
    DocumentTooLarge { name: String, max: u64, actual: u64 },
    /// A document has a disallowed content type / extension.
    InvalidContentType { name: String, content_type: String },
    /// No recipients specified.
    NoRecipients,
    /// Too many recipients.
    TooManyRecipients { max: usize, actual: usize },
    /// An email address is invalid.
    InvalidEmail { email: String },
    /// A recipient ID appears more than once.
    DuplicateRecipientId { recipient_id: String },
}

impl fmt::Display for EnvelopeValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySubject => write!(f, "email subject must not be empty"),
            Self::SubjectTooLong { max, actual } => {
                write!(f, "email subject too long ({actual} chars, max {max})")
            }
            Self::NoDocuments => write!(f, "at least one document is required"),
            Self::TooManyDocuments { max, actual } => {
                write!(f, "too many documents ({actual}, max {max})")
            }
            Self::DocumentTooLarge { name, max, actual } => {
                write!(
                    f,
                    "document \"{name}\" too large ({actual} bytes, max {max})"
                )
            }
            Self::InvalidContentType { name, content_type } => {
                write!(
                    f,
                    "document \"{name}\" has disallowed content type \"{content_type}\""
                )
            }
            Self::NoRecipients => write!(f, "at least one recipient is required"),
            Self::TooManyRecipients { max, actual } => {
                write!(f, "too many recipients ({actual}, max {max})")
            }
            Self::InvalidEmail { email } => {
                write!(f, "invalid email address: \"{email}\"")
            }
            Self::DuplicateRecipientId { recipient_id } => {
                write!(f, "duplicate recipient ID: \"{recipient_id}\"")
            }
        }
    }
}

impl std::error::Error for EnvelopeValidationError {}

// ── Audit events ─────────────────────────────────────────────────────

/// Actions tracked by audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    /// Envelope was created.
    Created,
    /// Envelope metadata was updated.
    Updated,
    /// A document was added.
    DocumentAdded,
}

/// An audit event recording an envelope lifecycle action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeAuditEvent {
    /// Timestamp of the event (ISO-8601).
    pub timestamp: String,
    /// What happened.
    pub action: AuditAction,
    /// Envelope ID, if known.
    pub envelope_id: Option<String>,
    /// Number of documents at the time of the event.
    pub document_count: usize,
    /// Number of recipients at the time of the event.
    pub recipient_count: usize,
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Creates a minimal valid document for testing purposes.
#[cfg(test)]
fn test_doc(name: &str, ext: &str) -> Document {
    Document {
        document_id: "1".into(),
        name: name.into(),
        file_extension: ext.into(),
        content_type: format!("application/{ext}"),
        size_bytes: Some(1024),
        order: 1,
    }
}

/// Creates a minimal valid signer for testing purposes.
#[cfg(test)]
fn test_signer(id: &str, email: &str) -> Signer {
    Signer {
        email: email.into(),
        name: format!("Signer {id}"),
        recipient_id: id.into(),
        routing_order: 1,
        tabs: None,
    }
}

/// Creates a minimal valid CC recipient for testing purposes.
#[cfg(test)]
fn test_cc(id: &str, email: &str) -> CcRecipient {
    CcRecipient {
        email: email.into(),
        name: format!("CC {id}"),
        recipient_id: id.into(),
        routing_order: 2,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── EnvelopeStatus ───────────────────────────────────────────

    #[test]
    fn status_as_str() {
        assert_eq!(EnvelopeStatus::Created.as_str(), "created");
        assert_eq!(EnvelopeStatus::Sent.as_str(), "sent");
        assert_eq!(EnvelopeStatus::Delivered.as_str(), "delivered");
        assert_eq!(EnvelopeStatus::Signed.as_str(), "signed");
        assert_eq!(EnvelopeStatus::Completed.as_str(), "completed");
        assert_eq!(EnvelopeStatus::Declined.as_str(), "declined");
        assert_eq!(EnvelopeStatus::Voided.as_str(), "voided");
        assert_eq!(EnvelopeStatus::Draft.as_str(), "draft");
    }

    #[test]
    fn status_display() {
        assert_eq!(EnvelopeStatus::Created.to_string(), "created");
        assert_eq!(EnvelopeStatus::Draft.to_string(), "draft");
        assert_eq!(EnvelopeStatus::Voided.to_string(), "voided");
    }

    #[test]
    fn terminal_statuses() {
        assert!(EnvelopeStatus::Completed.is_terminal());
        assert!(EnvelopeStatus::Declined.is_terminal());
        assert!(EnvelopeStatus::Voided.is_terminal());
    }

    #[test]
    fn active_statuses() {
        assert!(EnvelopeStatus::Created.is_active());
        assert!(EnvelopeStatus::Sent.is_active());
        assert!(EnvelopeStatus::Delivered.is_active());
        assert!(EnvelopeStatus::Signed.is_active());
        assert!(EnvelopeStatus::Draft.is_active());
    }

    #[test]
    fn terminal_is_not_active() {
        assert!(!EnvelopeStatus::Completed.is_active());
        assert!(!EnvelopeStatus::Declined.is_active());
        assert!(!EnvelopeStatus::Voided.is_active());
    }

    #[test]
    fn active_is_not_terminal() {
        assert!(!EnvelopeStatus::Created.is_terminal());
        assert!(!EnvelopeStatus::Sent.is_terminal());
        assert!(!EnvelopeStatus::Delivered.is_terminal());
        assert!(!EnvelopeStatus::Signed.is_terminal());
        assert!(!EnvelopeStatus::Draft.is_terminal());
    }

    #[test]
    fn status_serde_roundtrip() {
        let s = EnvelopeStatus::Sent;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"sent\"");
        let back: EnvelopeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EnvelopeStatus::Sent);
    }

    #[test]
    fn status_serde_all_variants() {
        for status in &[
            EnvelopeStatus::Created,
            EnvelopeStatus::Sent,
            EnvelopeStatus::Delivered,
            EnvelopeStatus::Signed,
            EnvelopeStatus::Completed,
            EnvelopeStatus::Declined,
            EnvelopeStatus::Voided,
            EnvelopeStatus::Draft,
        ] {
            let json = serde_json::to_string(status).unwrap();
            let back: EnvelopeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, status);
        }
    }

    #[test]
    fn status_clone() {
        let s = EnvelopeStatus::Delivered;
        let cloned = s.clone();
        assert_eq!(s, EnvelopeStatus::Delivered);
        assert_eq!(cloned, EnvelopeStatus::Delivered);
    }

    #[test]
    fn status_debug() {
        let dbg = format!("{:?}", EnvelopeStatus::Signed);
        assert!(dbg.contains("Signed"));
    }

    #[test]
    fn status_equality() {
        assert_eq!(EnvelopeStatus::Draft, EnvelopeStatus::Draft);
        assert_ne!(EnvelopeStatus::Draft, EnvelopeStatus::Sent);
    }

    // ── Document ─────────────────────────────────────────────────

    #[test]
    fn document_validate_valid_pdf() {
        let doc = test_doc("contract.pdf", "pdf");
        let config = EnvelopeConfig::default();
        assert!(doc.validate(&config).is_ok());
    }

    #[test]
    fn document_validate_valid_docx() {
        let doc = test_doc("letter.docx", "docx");
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_validate_valid_doc() {
        let doc = test_doc("old.doc", "doc");
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_validate_valid_png() {
        let doc = test_doc("scan.png", "png");
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_validate_valid_jpg() {
        let doc = test_doc("photo.jpg", "jpg");
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_validate_empty_name() {
        let doc = test_doc("", "pdf");
        let err = doc.validate(&EnvelopeConfig::default()).unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidContentType { .. }));
    }

    #[test]
    fn document_validate_disallowed_extension() {
        let doc = test_doc("malware.exe", "exe");
        let err = doc.validate(&EnvelopeConfig::default()).unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidContentType { .. }));
    }

    #[test]
    fn document_validate_disallowed_zip() {
        let doc = test_doc("archive.zip", "zip");
        let err = doc.validate(&EnvelopeConfig::default()).unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidContentType { .. }));
    }

    #[test]
    fn document_validate_too_large() {
        let mut doc = test_doc("big.pdf", "pdf");
        doc.size_bytes = Some(30 * 1024 * 1024); // 30 MB
        let err = doc.validate(&EnvelopeConfig::default()).unwrap_err();
        match err {
            EnvelopeValidationError::DocumentTooLarge { name, max, actual } => {
                assert_eq!(name, "big.pdf");
                assert_eq!(max, DEFAULT_MAX_DOCUMENT_SIZE);
                assert_eq!(actual, 30 * 1024 * 1024);
            }
            other => panic!("expected DocumentTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn document_validate_exactly_at_limit() {
        let mut doc = test_doc("exact.pdf", "pdf");
        doc.size_bytes = Some(DEFAULT_MAX_DOCUMENT_SIZE);
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_validate_one_over_limit() {
        let mut doc = test_doc("over.pdf", "pdf");
        doc.size_bytes = Some(DEFAULT_MAX_DOCUMENT_SIZE + 1);
        assert!(doc.validate(&EnvelopeConfig::default()).is_err());
    }

    #[test]
    fn document_validate_no_size() {
        let mut doc = test_doc("nosize.pdf", "pdf");
        doc.size_bytes = None;
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_validate_zero_size() {
        let mut doc = test_doc("empty.pdf", "pdf");
        doc.size_bytes = Some(0);
        assert!(doc.validate(&EnvelopeConfig::default()).is_ok());
    }

    #[test]
    fn document_serde_roundtrip() {
        let doc = test_doc("contract.pdf", "pdf");
        let json = serde_json::to_string(&doc).unwrap();
        let back: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "contract.pdf");
        assert_eq!(back.file_extension, "pdf");
        assert_eq!(back.order, 1);
    }

    #[test]
    fn document_clone() {
        let doc = test_doc("a.pdf", "pdf");
        let cloned = doc.clone();
        drop(doc);
        assert_eq!(cloned.name, "a.pdf");
    }

    #[test]
    fn document_debug() {
        let doc = test_doc("a.pdf", "pdf");
        let dbg = format!("{doc:?}");
        assert!(dbg.contains("Document"));
    }

    // ── Signer / CcRecipient / CarbonCopy ────────────────────────

    #[test]
    fn signer_serde_roundtrip() {
        let s = test_signer("1", "alice@example.com");
        let json = serde_json::to_string(&s).unwrap();
        let back: Signer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.email, "alice@example.com");
        assert_eq!(back.recipient_id, "1");
    }

    #[test]
    fn signer_with_tabs() {
        let s = Signer {
            email: "bob@example.com".into(),
            name: "Bob".into(),
            recipient_id: "2".into(),
            routing_order: 1,
            tabs: Some(json!({"signHereTabs": [{"x": 100, "y": 200}]})),
        };
        assert!(s.tabs.is_some());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("signHereTabs"));
    }

    #[test]
    fn signer_without_tabs() {
        let s = test_signer("3", "no-tabs@example.com");
        assert!(s.tabs.is_none());
        let json = serde_json::to_string(&s).unwrap();
        let back: Signer = serde_json::from_str(&json).unwrap();
        assert!(back.tabs.is_none());
    }

    #[test]
    fn signer_clone() {
        let s = test_signer("4", "clone@example.com");
        let cloned = s.clone();
        drop(s);
        assert_eq!(cloned.email, "clone@example.com");
    }

    #[test]
    fn signer_debug() {
        let s = test_signer("5", "dbg@example.com");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Signer"));
    }

    #[test]
    fn cc_recipient_serde_roundtrip() {
        let cc = test_cc("10", "cc@example.com");
        let json = serde_json::to_string(&cc).unwrap();
        let back: CcRecipient = serde_json::from_str(&json).unwrap();
        assert_eq!(back.email, "cc@example.com");
        assert_eq!(back.routing_order, 2);
    }

    #[test]
    fn cc_recipient_clone() {
        let cc = test_cc("11", "cc2@example.com");
        let cloned = cc.clone();
        drop(cc);
        assert_eq!(cloned.recipient_id, "11");
    }

    #[test]
    fn cc_recipient_debug() {
        let cc = test_cc("12", "cc3@example.com");
        let dbg = format!("{cc:?}");
        assert!(dbg.contains("CcRecipient"));
    }

    #[test]
    fn carbon_copy_serde_roundtrip() {
        let cc = CarbonCopy {
            email: "legal@example.com".into(),
            name: "Legal".into(),
            recipient_id: "20".into(),
            routing_order: 3,
        };
        let json = serde_json::to_string(&cc).unwrap();
        let back: CarbonCopy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.email, "legal@example.com");
        assert_eq!(back.routing_order, 3);
    }

    #[test]
    fn carbon_copy_clone() {
        let cc = CarbonCopy {
            email: "a@b.com".into(),
            name: "A".into(),
            recipient_id: "21".into(),
            routing_order: 1,
        };
        let cloned = cc.clone();
        drop(cc);
        assert_eq!(cloned.recipient_id, "21");
    }

    #[test]
    fn carbon_copy_debug() {
        let cc = CarbonCopy {
            email: "a@b.com".into(),
            name: "A".into(),
            recipient_id: "22".into(),
            routing_order: 1,
        };
        let dbg = format!("{cc:?}");
        assert!(dbg.contains("CarbonCopy"));
    }

    // ── Recipients ───────────────────────────────────────────────

    #[test]
    fn recipients_serde_roundtrip() {
        let r = Recipients {
            signers: vec![test_signer("1", "s@x.com")],
            cc_recipients: vec![test_cc("2", "c@x.com")],
            carbon_copies: vec![],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Recipients = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signers.len(), 1);
        assert_eq!(back.cc_recipients.len(), 1);
        assert!(back.carbon_copies.is_empty());
    }

    #[test]
    fn recipients_empty() {
        let r = Recipients {
            signers: vec![],
            cc_recipients: vec![],
            carbon_copies: vec![],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Recipients = serde_json::from_str(&json).unwrap();
        assert!(back.signers.is_empty());
    }

    #[test]
    fn recipients_clone() {
        let r = Recipients {
            signers: vec![test_signer("1", "s@x.com")],
            cc_recipients: vec![],
            carbon_copies: vec![],
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.signers.len(), 1);
    }

    #[test]
    fn recipients_debug() {
        let r = Recipients {
            signers: vec![],
            cc_recipients: vec![],
            carbon_copies: vec![],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Recipients"));
    }

    // ── Envelope ─────────────────────────────────────────────────

    #[test]
    fn envelope_serde_roundtrip() {
        let e = Envelope {
            envelope_id: Some("env-1".into()),
            status: EnvelopeStatus::Draft,
            email_subject: "Sign this".into(),
            email_body: Some("Please sign".into()),
            documents: vec![test_doc("c.pdf", "pdf")],
            recipients: None,
            created_at: Some("2026-01-01T00:00:00Z".into()),
            updated_at: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope_id, Some("env-1".into()));
        assert_eq!(back.status, EnvelopeStatus::Draft);
        assert_eq!(back.email_subject, "Sign this");
    }

    #[test]
    fn envelope_no_id() {
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "New".into(),
            email_body: None,
            documents: vec![],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert!(e.envelope_id.is_none());
    }

    #[test]
    fn envelope_clone() {
        let e = Envelope {
            envelope_id: Some("env-c".into()),
            status: EnvelopeStatus::Sent,
            email_subject: "Clone test".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.envelope_id, Some("env-c".into()));
        assert_eq!(cloned.documents.len(), 1);
    }

    #[test]
    fn envelope_debug() {
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Debug".into(),
            email_body: None,
            documents: vec![],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Envelope"));
    }

    // ── EnvelopeConfig ───────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let c = EnvelopeConfig::default();
        assert_eq!(c.max_document_size_bytes, 25 * 1024 * 1024);
        assert_eq!(c.max_documents, 10);
        assert_eq!(c.max_recipients, 20);
        assert_eq!(c.max_subject_length, 100);
    }

    #[test]
    fn config_default_allowed_types() {
        let c = EnvelopeConfig::default();
        assert!(c.allowed_content_types.contains("pdf"));
        assert!(c.allowed_content_types.contains("docx"));
        assert!(c.allowed_content_types.contains("doc"));
        assert!(c.allowed_content_types.contains("png"));
        assert!(c.allowed_content_types.contains("jpg"));
        assert!(!c.allowed_content_types.contains("exe"));
        assert!(!c.allowed_content_types.contains("zip"));
    }

    #[test]
    fn config_validate_document() {
        let c = EnvelopeConfig::default();
        assert!(c.validate_document(&test_doc("ok.pdf", "pdf")).is_ok());
    }

    #[test]
    fn config_validate_document_bad_ext() {
        let c = EnvelopeConfig::default();
        let err = c.validate_document(&test_doc("bad.txt", "txt")).unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidContentType { .. }));
    }

    #[test]
    fn config_validate_envelope_ok() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Valid subject".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![test_signer("1", "a@b.com")],
                cc_recipients: vec![],
                carbon_copies: vec![],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(c.validate_envelope(&e).is_ok());
    }

    #[test]
    fn config_validate_envelope_empty_subject() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: String::new(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert_eq!(c.validate_envelope(&e).unwrap_err(), EnvelopeValidationError::EmptySubject);
    }

    #[test]
    fn config_validate_envelope_subject_too_long() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "x".repeat(101),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::SubjectTooLong { max: 100, actual: 101 }
        ));
    }

    #[test]
    fn config_validate_envelope_no_documents() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert_eq!(c.validate_envelope(&e).unwrap_err(), EnvelopeValidationError::NoDocuments);
    }

    #[test]
    fn config_validate_envelope_too_many_documents() {
        let c = EnvelopeConfig::default();
        let docs: Vec<Document> = (0..11)
            .map(|i| {
                let mut d = test_doc(&format!("doc{i}.pdf"), "pdf");
                d.document_id = i.to_string();
                d
            })
            .collect();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: docs,
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::TooManyDocuments { max: 10, actual: 11 }
        ));
    }

    #[test]
    fn config_validate_envelope_bad_document_type() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.exe", "exe")],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::InvalidContentType { .. }
        ));
    }

    #[test]
    fn config_validate_envelope_too_many_recipients() {
        let c = EnvelopeConfig {
            max_recipients: 2,
            ..EnvelopeConfig::default()
        };
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![
                    test_signer("1", "a@b.com"),
                    test_signer("2", "b@b.com"),
                    test_signer("3", "c@b.com"),
                ],
                cc_recipients: vec![],
                carbon_copies: vec![],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::TooManyRecipients { max: 2, actual: 3 }
        ));
    }

    #[test]
    fn config_validate_envelope_duplicate_signer_ids() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![
                    test_signer("1", "a@b.com"),
                    test_signer("1", "b@b.com"),
                ],
                cc_recipients: vec![],
                carbon_copies: vec![],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::DuplicateRecipientId { .. }
        ));
    }

    #[test]
    fn config_validate_envelope_duplicate_across_types() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![test_signer("1", "a@b.com")],
                cc_recipients: vec![test_cc("1", "cc@b.com")],
                carbon_copies: vec![],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::DuplicateRecipientId { .. }
        ));
    }

    #[test]
    fn config_validate_envelope_invalid_signer_email() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![test_signer("1", "not-an-email")],
                cc_recipients: vec![],
                carbon_copies: vec![],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::InvalidEmail { .. }
        ));
    }

    #[test]
    fn config_validate_envelope_invalid_cc_email() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![],
                cc_recipients: vec![test_cc("1", "bad")],
                carbon_copies: vec![],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::InvalidEmail { .. }
        ));
    }

    #[test]
    fn config_validate_envelope_invalid_carbon_copy_email() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![],
                cc_recipients: vec![],
                carbon_copies: vec![CarbonCopy {
                    email: "nope".into(),
                    name: "Bad".into(),
                    recipient_id: "1".into(),
                    routing_order: 1,
                }],
            }),
            created_at: None,
            updated_at: None,
        };
        assert!(matches!(
            c.validate_envelope(&e).unwrap_err(),
            EnvelopeValidationError::InvalidEmail { .. }
        ));
    }

    #[test]
    fn config_validate_envelope_no_recipients() {
        let c = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: "Sub".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        // No recipients field — validation passes (recipients are optional at
        // the envelope level, only required by the builder).
        assert!(c.validate_envelope(&e).is_ok());
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = EnvelopeConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: EnvelopeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_documents, c.max_documents);
        assert_eq!(back.max_recipients, c.max_recipients);
    }

    #[test]
    fn config_clone() {
        let c = EnvelopeConfig::default();
        let cloned = c.clone();
        drop(c);
        assert_eq!(cloned.max_documents, 10);
    }

    #[test]
    fn config_debug() {
        let c = EnvelopeConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("EnvelopeConfig"));
    }

    #[test]
    fn config_custom_limits() {
        let c = EnvelopeConfig {
            max_document_size_bytes: 1024,
            max_documents: 2,
            allowed_content_types: std::iter::once("pdf".to_string()).collect(),
            max_recipients: 3,
            max_subject_length: 50,
        };
        let mut doc = test_doc("small.pdf", "pdf");
        doc.size_bytes = Some(2048);
        assert!(c.validate_document(&doc).is_err());
        doc.size_bytes = Some(512);
        assert!(c.validate_document(&doc).is_ok());
        let docx = test_doc("nope.docx", "docx");
        assert!(c.validate_document(&docx).is_err());
    }

    // ── EnvelopeBuilder ──────────────────────────────────────────

    #[test]
    fn builder_minimal_valid() {
        let env = EnvelopeBuilder::new("Please sign")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "alice@example.com"))
            .build()
            .unwrap();
        assert_eq!(env.status, EnvelopeStatus::Draft);
        assert_eq!(env.email_subject, "Please sign");
        assert!(env.envelope_id.is_none());
        assert_eq!(env.documents.len(), 1);
    }

    #[test]
    fn builder_with_body() {
        let env = EnvelopeBuilder::new("Subject")
            .with_body("Body text")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env.email_body, Some("Body text".into()));
    }

    #[test]
    fn builder_multiple_documents() {
        let mut d1 = test_doc("a.pdf", "pdf");
        d1.document_id = "1".into();
        let mut d2 = test_doc("b.docx", "docx");
        d2.document_id = "2".into();
        let env = EnvelopeBuilder::new("Multi-doc")
            .add_document(d1)
            .add_document(d2)
            .add_signer(test_signer("1", "s@x.com"))
            .build()
            .unwrap();
        assert_eq!(env.documents.len(), 2);
    }

    #[test]
    fn builder_multiple_signers() {
        let env = EnvelopeBuilder::new("Multi-sign")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@x.com"))
            .add_signer(test_signer("2", "b@x.com"))
            .build()
            .unwrap();
        let recips = env.recipients.unwrap();
        assert_eq!(recips.signers.len(), 2);
    }

    #[test]
    fn builder_with_cc() {
        let env = EnvelopeBuilder::new("With CC")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "s@x.com"))
            .add_cc(test_cc("2", "cc@x.com"))
            .build()
            .unwrap();
        let recips = env.recipients.unwrap();
        assert_eq!(recips.signers.len(), 1);
        assert_eq!(recips.cc_recipients.len(), 1);
    }

    #[test]
    fn builder_empty_subject() {
        let err = EnvelopeBuilder::new("")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap_err();
        assert_eq!(err, EnvelopeValidationError::EmptySubject);
    }

    #[test]
    fn builder_subject_too_long() {
        let err = EnvelopeBuilder::new("x".repeat(101))
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::SubjectTooLong { .. }));
    }

    #[test]
    fn builder_subject_exactly_100() {
        let env = EnvelopeBuilder::new("x".repeat(100))
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env.email_subject.len(), 100);
    }

    #[test]
    fn builder_no_documents() {
        let err = EnvelopeBuilder::new("Sub")
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap_err();
        assert_eq!(err, EnvelopeValidationError::NoDocuments);
    }

    #[test]
    fn builder_too_many_documents() {
        let mut b = EnvelopeBuilder::new("Sub");
        for i in 0..11 {
            let mut d = test_doc(&format!("d{i}.pdf"), "pdf");
            d.document_id = i.to_string();
            b = b.add_document(d);
        }
        b = b.add_signer(test_signer("1", "a@b.com"));
        let err = b.build().unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::TooManyDocuments { .. }));
    }

    #[test]
    fn builder_bad_content_type() {
        let err = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("a.exe", "exe"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidContentType { .. }));
    }

    #[test]
    fn builder_document_too_large() {
        let mut doc = test_doc("big.pdf", "pdf");
        doc.size_bytes = Some(30 * 1024 * 1024);
        let err = EnvelopeBuilder::new("Sub")
            .add_document(doc)
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::DocumentTooLarge { .. }));
    }

    #[test]
    fn builder_no_recipients() {
        let err = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("c.pdf", "pdf"))
            .build()
            .unwrap_err();
        assert_eq!(err, EnvelopeValidationError::NoRecipients);
    }

    #[test]
    fn builder_cc_only_counts_as_recipient() {
        let env = EnvelopeBuilder::new("CC only")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_cc(test_cc("1", "cc@example.com"))
            .build()
            .unwrap();
        assert!(env.recipients.is_some());
    }

    #[test]
    fn builder_too_many_recipients() {
        let mut b = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("c.pdf", "pdf"))
            .with_config(EnvelopeConfig {
                max_recipients: 2,
                ..EnvelopeConfig::default()
            });
        for i in 0..3 {
            b = b.add_signer(test_signer(&i.to_string(), &format!("s{i}@x.com")));
        }
        let err = b.build().unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::TooManyRecipients { .. }));
    }

    #[test]
    fn builder_duplicate_signer_ids() {
        let err = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .add_signer(test_signer("1", "c@b.com"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::DuplicateRecipientId { .. }));
    }

    #[test]
    fn builder_duplicate_across_signer_cc() {
        let err = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .add_cc(test_cc("1", "cc@b.com"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::DuplicateRecipientId { .. }));
    }

    #[test]
    fn builder_invalid_signer_email() {
        let err = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "nope"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidEmail { .. }));
    }

    #[test]
    fn builder_invalid_cc_email() {
        let err = EnvelopeBuilder::new("Sub")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "ok@x.com"))
            .add_cc(test_cc("2", "bad"))
            .build()
            .unwrap_err();
        assert!(matches!(err, EnvelopeValidationError::InvalidEmail { .. }));
    }

    #[test]
    fn builder_with_custom_config() {
        let config = EnvelopeConfig {
            max_document_size_bytes: 2048,
            max_documents: 1,
            allowed_content_types: std::iter::once("pdf".to_string()).collect(),
            max_recipients: 1,
            max_subject_length: 20,
        };
        let env = EnvelopeBuilder::new("Short")
            .with_config(config)
            .add_document(test_doc("a.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env.documents.len(), 1);
    }

    #[test]
    fn builder_clone() {
        let b = EnvelopeBuilder::new("Clone me")
            .add_document(test_doc("a.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"));
        let cloned = b.clone();
        drop(b);
        let env = cloned.build().unwrap();
        assert_eq!(env.email_subject, "Clone me");
    }

    #[test]
    fn builder_debug() {
        let b = EnvelopeBuilder::new("Debug");
        let dbg = format!("{b:?}");
        assert!(dbg.contains("EnvelopeBuilder"));
    }

    #[test]
    fn builder_produces_draft_status() {
        let env = EnvelopeBuilder::new("Draft test")
            .add_document(test_doc("a.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env.status, EnvelopeStatus::Draft);
        assert!(env.status.is_active());
        assert!(!env.status.is_terminal());
    }

    #[test]
    fn builder_no_envelope_id() {
        let env = EnvelopeBuilder::new("No ID")
            .add_document(test_doc("a.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert!(env.envelope_id.is_none());
        assert!(env.created_at.is_none());
        assert!(env.updated_at.is_none());
    }

    #[test]
    fn builder_carbon_copies_empty() {
        let env = EnvelopeBuilder::new("CC empty")
            .add_document(test_doc("a.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        let recips = env.recipients.unwrap();
        assert!(recips.carbon_copies.is_empty());
    }

    // ── EnvelopeValidationError ──────────────────────────────────

    #[test]
    fn error_display_empty_subject() {
        assert_eq!(
            EnvelopeValidationError::EmptySubject.to_string(),
            "email subject must not be empty"
        );
    }

    #[test]
    fn error_display_subject_too_long() {
        let e = EnvelopeValidationError::SubjectTooLong { max: 100, actual: 150 };
        assert_eq!(e.to_string(), "email subject too long (150 chars, max 100)");
    }

    #[test]
    fn error_display_no_documents() {
        assert_eq!(
            EnvelopeValidationError::NoDocuments.to_string(),
            "at least one document is required"
        );
    }

    #[test]
    fn error_display_too_many_documents() {
        let e = EnvelopeValidationError::TooManyDocuments { max: 10, actual: 15 };
        assert_eq!(e.to_string(), "too many documents (15, max 10)");
    }

    #[test]
    fn error_display_document_too_large() {
        let e = EnvelopeValidationError::DocumentTooLarge {
            name: "big.pdf".into(),
            max: 1024,
            actual: 2048,
        };
        assert_eq!(
            e.to_string(),
            "document \"big.pdf\" too large (2048 bytes, max 1024)"
        );
    }

    #[test]
    fn error_display_invalid_content_type() {
        let e = EnvelopeValidationError::InvalidContentType {
            name: "a.exe".into(),
            content_type: "exe".into(),
        };
        assert_eq!(
            e.to_string(),
            "document \"a.exe\" has disallowed content type \"exe\""
        );
    }

    #[test]
    fn error_display_no_recipients() {
        assert_eq!(
            EnvelopeValidationError::NoRecipients.to_string(),
            "at least one recipient is required"
        );
    }

    #[test]
    fn error_display_too_many_recipients() {
        let e = EnvelopeValidationError::TooManyRecipients { max: 20, actual: 25 };
        assert_eq!(e.to_string(), "too many recipients (25, max 20)");
    }

    #[test]
    fn error_display_invalid_email() {
        let e = EnvelopeValidationError::InvalidEmail { email: "bad".into() };
        assert_eq!(e.to_string(), "invalid email address: \"bad\"");
    }

    #[test]
    fn error_display_duplicate_recipient_id() {
        let e = EnvelopeValidationError::DuplicateRecipientId { recipient_id: "1".into() };
        assert_eq!(e.to_string(), "duplicate recipient ID: \"1\"");
    }

    #[test]
    fn error_is_std_error() {
        let e = EnvelopeValidationError::EmptySubject;
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn error_equality() {
        assert_eq!(
            EnvelopeValidationError::EmptySubject,
            EnvelopeValidationError::EmptySubject
        );
        assert_ne!(
            EnvelopeValidationError::EmptySubject,
            EnvelopeValidationError::NoDocuments
        );
    }

    #[test]
    fn error_clone() {
        let e = EnvelopeValidationError::DocumentTooLarge {
            name: "a.pdf".into(),
            max: 100,
            actual: 200,
        };
        let cloned = e.clone();
        drop(e);
        assert!(matches!(cloned, EnvelopeValidationError::DocumentTooLarge { .. }));
    }

    #[test]
    fn error_debug() {
        let e = EnvelopeValidationError::NoRecipients;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("NoRecipients"));
    }

    // ── Email validation ─────────────────────────────────────────

    #[test]
    fn email_valid() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("a@b.co"));
        assert!(is_valid_email("user+tag@domain.org"));
    }

    #[test]
    fn email_missing_at() {
        assert!(!is_valid_email("userexample.com"));
    }

    #[test]
    fn email_no_local() {
        assert!(!is_valid_email("@example.com"));
    }

    #[test]
    fn email_no_domain() {
        assert!(!is_valid_email("user@"));
    }

    #[test]
    fn email_no_dot_in_domain() {
        assert!(!is_valid_email("user@domain"));
    }

    #[test]
    fn email_multiple_ats() {
        assert!(!is_valid_email("user@mid@example.com"));
    }

    #[test]
    fn email_empty() {
        assert!(!is_valid_email(""));
    }

    // ── AuditEvent ───────────────────────────────────────────────

    #[test]
    fn audit_action_serde() {
        let a = AuditAction::Created;
        let json = serde_json::to_string(&a).unwrap();
        let back: AuditAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AuditAction::Created);
    }

    #[test]
    fn audit_action_all_variants() {
        for action in &[AuditAction::Created, AuditAction::Updated, AuditAction::DocumentAdded] {
            let json = serde_json::to_string(action).unwrap();
            let back: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, action);
        }
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let ev = EnvelopeAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            action: AuditAction::Created,
            envelope_id: Some("env-1".into()),
            document_count: 2,
            recipient_count: 3,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: EnvelopeAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp, "2026-03-09T12:00:00Z");
        assert_eq!(back.action, AuditAction::Created);
        assert_eq!(back.envelope_id, Some("env-1".into()));
        assert_eq!(back.document_count, 2);
        assert_eq!(back.recipient_count, 3);
    }

    #[test]
    fn audit_event_no_envelope_id() {
        let ev = EnvelopeAuditEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: AuditAction::DocumentAdded,
            envelope_id: None,
            document_count: 1,
            recipient_count: 0,
        };
        assert!(ev.envelope_id.is_none());
    }

    #[test]
    fn audit_event_clone() {
        let ev = EnvelopeAuditEvent {
            timestamp: "t".into(),
            action: AuditAction::Updated,
            envelope_id: Some("e".into()),
            document_count: 0,
            recipient_count: 0,
        };
        let cloned = ev.clone();
        drop(ev);
        assert_eq!(cloned.action, AuditAction::Updated);
    }

    #[test]
    fn audit_event_debug() {
        let ev = EnvelopeAuditEvent {
            timestamp: "t".into(),
            action: AuditAction::Created,
            envelope_id: None,
            document_count: 0,
            recipient_count: 0,
        };
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("EnvelopeAuditEvent"));
    }

    #[test]
    fn audit_action_clone() {
        let a = AuditAction::DocumentAdded;
        let cloned = a.clone();
        assert_eq!(a, AuditAction::DocumentAdded);
        assert_eq!(cloned, AuditAction::DocumentAdded);
    }

    #[test]
    fn audit_action_debug() {
        let dbg = format!("{:?}", AuditAction::Updated);
        assert!(dbg.contains("Updated"));
    }

    // ── Content-type allowlist edge cases ────────────────────────

    #[test]
    fn allowlist_case_sensitive() {
        let doc = test_doc("upper.PDF", "PDF");
        // Default allowlist has "pdf" not "PDF" — should fail.
        assert!(doc.validate(&EnvelopeConfig::default()).is_err());
    }

    #[test]
    fn allowlist_custom_type() {
        let mut config = EnvelopeConfig::default();
        config.allowed_content_types.insert("xlsx".into());
        let doc = test_doc("sheet.xlsx", "xlsx");
        assert!(doc.validate(&config).is_ok());
    }

    #[test]
    fn allowlist_remove_default_type() {
        let mut config = EnvelopeConfig::default();
        config.allowed_content_types.remove("pdf");
        let doc = test_doc("no-pdf.pdf", "pdf");
        assert!(doc.validate(&config).is_err());
    }

    // ── Serde from JSON values ───────────────────────────────────

    #[test]
    fn envelope_from_json_value() {
        let e: Envelope = serde_json::from_value(json!({
            "envelope_id": "e-100",
            "status": "sent",
            "email_subject": "Review",
            "documents": [],
        }))
        .unwrap();
        assert_eq!(e.envelope_id, Some("e-100".into()));
        assert_eq!(e.status, EnvelopeStatus::Sent);
    }

    #[test]
    fn document_from_json_value() {
        let d: Document = serde_json::from_value(json!({
            "document_id": "d-1",
            "name": "contract.pdf",
            "file_extension": "pdf",
            "content_type": "application/pdf",
            "size_bytes": 12345,
            "order": 1,
        }))
        .unwrap();
        assert_eq!(d.document_id, "d-1");
        assert_eq!(d.size_bytes, Some(12345));
    }

    #[test]
    fn signer_from_json_value() {
        let s: Signer = serde_json::from_value(json!({
            "email": "alice@example.com",
            "name": "Alice",
            "recipient_id": "r1",
            "routing_order": 1,
        }))
        .unwrap();
        assert_eq!(s.email, "alice@example.com");
        assert!(s.tabs.is_none());
    }

    // ── Builder chaining ─────────────────────────────────────────

    #[test]
    fn builder_chaining_order_irrelevant() {
        // Signer before document should still work.
        let env = EnvelopeBuilder::new("Chain test")
            .add_signer(test_signer("1", "a@b.com"))
            .add_document(test_doc("c.pdf", "pdf"))
            .build()
            .unwrap();
        assert_eq!(env.documents.len(), 1);
        assert_eq!(env.recipients.as_ref().unwrap().signers.len(), 1);
    }

    #[test]
    fn builder_body_after_document() {
        let env = EnvelopeBuilder::new("Body after doc")
            .add_document(test_doc("c.pdf", "pdf"))
            .with_body("Late body")
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env.email_body, Some("Late body".into()));
    }

    #[test]
    fn builder_config_after_recipients() {
        let config = EnvelopeConfig {
            max_recipients: 5,
            ..EnvelopeConfig::default()
        };
        let env = EnvelopeBuilder::new("Config late")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .with_config(config)
            .build()
            .unwrap();
        assert_eq!(env.documents.len(), 1);
    }

    // ── Document ordering ────────────────────────────────────────

    #[test]
    fn document_order_preserved() {
        let mut d1 = test_doc("first.pdf", "pdf");
        d1.document_id = "1".into();
        d1.order = 1;
        let mut d2 = test_doc("second.pdf", "pdf");
        d2.document_id = "2".into();
        d2.order = 2;
        let mut d3 = test_doc("third.pdf", "pdf");
        d3.document_id = "3".into();
        d3.order = 3;
        let env = EnvelopeBuilder::new("Order test")
            .add_document(d1)
            .add_document(d2)
            .add_document(d3)
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env.documents[0].order, 1);
        assert_eq!(env.documents[1].order, 2);
        assert_eq!(env.documents[2].order, 3);
    }

    // ── Routing order ────────────────────────────────────────────

    #[test]
    fn signer_routing_order() {
        let s = Signer {
            email: "a@b.com".into(),
            name: "A".into(),
            recipient_id: "1".into(),
            routing_order: 5,
            tabs: None,
        };
        assert_eq!(s.routing_order, 5);
    }

    #[test]
    fn cc_routing_order() {
        let cc = CcRecipient {
            email: "c@d.com".into(),
            name: "C".into(),
            recipient_id: "2".into(),
            routing_order: 10,
        };
        assert_eq!(cc.routing_order, 10);
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn builder_subject_with_unicode() {
        let env = EnvelopeBuilder::new("Please sign the Vertrag")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert!(env.email_subject.contains("Vertrag"));
    }

    #[test]
    fn builder_empty_body_vs_none() {
        let env = EnvelopeBuilder::new("No body")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert!(env.email_body.is_none());

        let env2 = EnvelopeBuilder::new("Empty body")
            .with_body("")
            .add_document(test_doc("c.pdf", "pdf"))
            .add_signer(test_signer("1", "a@b.com"))
            .build()
            .unwrap();
        assert_eq!(env2.email_body, Some(String::new()));
    }

    #[test]
    fn document_validate_custom_small_limit() {
        let config = EnvelopeConfig {
            max_document_size_bytes: 100,
            ..EnvelopeConfig::default()
        };
        let mut doc = test_doc("tiny.pdf", "pdf");
        doc.size_bytes = Some(101);
        assert!(doc.validate(&config).is_err());
        doc.size_bytes = Some(100);
        assert!(doc.validate(&config).is_ok());
    }

    #[test]
    fn config_empty_allowlist_rejects_all() {
        let config = EnvelopeConfig {
            allowed_content_types: HashSet::new(),
            ..EnvelopeConfig::default()
        };
        assert!(config.validate_document(&test_doc("a.pdf", "pdf")).is_err());
    }

    #[test]
    fn envelope_with_all_recipient_types() {
        let e = Envelope {
            envelope_id: Some("full".into()),
            status: EnvelopeStatus::Created,
            email_subject: "Full recipients".into(),
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: Some(Recipients {
                signers: vec![test_signer("1", "s@x.com")],
                cc_recipients: vec![test_cc("2", "cc@x.com")],
                carbon_copies: vec![CarbonCopy {
                    email: "copy@x.com".into(),
                    name: "Copy".into(),
                    recipient_id: "3".into(),
                    routing_order: 3,
                }],
            }),
            created_at: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        let recips = back.recipients.unwrap();
        assert_eq!(recips.signers.len(), 1);
        assert_eq!(recips.cc_recipients.len(), 1);
        assert_eq!(recips.carbon_copies.len(), 1);
    }

    #[test]
    fn envelope_status_from_json_string() {
        let s: EnvelopeStatus = serde_json::from_str("\"completed\"").unwrap();
        assert_eq!(s, EnvelopeStatus::Completed);
        assert!(s.is_terminal());
    }

    #[test]
    fn envelope_subject_at_max_length() {
        let subject = "a".repeat(100);
        let config = EnvelopeConfig::default();
        let e = Envelope {
            envelope_id: None,
            status: EnvelopeStatus::Draft,
            email_subject: subject,
            email_body: None,
            documents: vec![test_doc("a.pdf", "pdf")],
            recipients: None,
            created_at: None,
            updated_at: None,
        };
        assert!(config.validate_envelope(&e).is_ok());
    }

    #[test]
    fn builder_ten_documents_ok() {
        let mut b = EnvelopeBuilder::new("Max docs");
        for i in 0..10 {
            let mut d = test_doc(&format!("d{i}.pdf"), "pdf");
            d.document_id = i.to_string();
            b = b.add_document(d);
        }
        b = b.add_signer(test_signer("1", "a@b.com"));
        assert!(b.build().is_ok());
    }

    #[test]
    fn builder_twenty_recipients_ok() {
        let mut b = EnvelopeBuilder::new("Max recips")
            .add_document(test_doc("a.pdf", "pdf"));
        for i in 0..20 {
            b = b.add_signer(test_signer(&i.to_string(), &format!("s{i}@x.com")));
        }
        assert!(b.build().is_ok());
    }

    #[test]
    fn builder_twenty_one_recipients_fails() {
        let mut b = EnvelopeBuilder::new("Over recips")
            .add_document(test_doc("a.pdf", "pdf"));
        for i in 0..21 {
            b = b.add_signer(test_signer(&i.to_string(), &format!("s{i}@x.com")));
        }
        assert!(matches!(
            b.build().unwrap_err(),
            EnvelopeValidationError::TooManyRecipients { .. }
        ));
    }
}
