//! `DocuSign` recipient and tab/field configuration.
//!
//! Provides typed, safe configuration of envelope recipients (signers, CC, etc.)
//! with routing order, and tab/field placement using both coordinate-based and
//! anchor-based positioning.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// RecipientRole
// ---------------------------------------------------------------------------

/// Role a recipient plays in a `DocuSign` envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecipientRole {
    /// Must sign the document.
    Signer,
    /// Receives a carbon copy (no signing required).
    CarbonCopy,
    /// Must confirm receipt via a certified delivery.
    CertifiedDelivery,
    /// Signs in person on behalf of the host signer.
    InPersonSigner,
    /// Can edit the envelope before it is sent.
    Editor,
    /// Acts as an agent for another signer.
    Agent,
    /// Routes the envelope without signing.
    Intermediary,
    /// Represents an electronic seal.
    Seal,
}

impl RecipientRole {
    /// Returns the `DocuSign` API string for this role.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Signer => "signer",
            Self::CarbonCopy => "carbonCopy",
            Self::CertifiedDelivery => "certifiedDelivery",
            Self::InPersonSigner => "inPersonSigner",
            Self::Editor => "editor",
            Self::Agent => "agent",
            Self::Intermediary => "intermediary",
            Self::Seal => "seal",
        }
    }

    /// Returns `true` if this role requires a signature.
    #[must_use]
    pub const fn requires_signature(&self) -> bool {
        matches!(self, Self::Signer | Self::InPersonSigner)
    }
}

impl fmt::Display for RecipientRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Recipient
// ---------------------------------------------------------------------------

/// A recipient to be added to a `DocuSign` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    /// Recipient email address.
    pub email: String,
    /// Recipient display name.
    pub name: String,
    /// The role this recipient plays.
    pub role: RecipientRole,
    /// Unique recipient identifier within the envelope.
    pub recipient_id: String,
    /// Routing order (1-based). Lower numbers receive first.
    pub routing_order: u32,
    /// Optional access code the recipient must enter to view the envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_code: Option<String>,
    /// Whether to require ID verification for this recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_check: Option<bool>,
}

/// Errors from validating a [`Recipient`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientValidationError {
    /// Email is empty.
    EmptyEmail,
    /// Email does not contain `@`.
    InvalidEmailFormat,
    /// Name is empty.
    EmptyName,
    /// Recipient ID is empty.
    EmptyRecipientId,
    /// Routing order is zero (must be >= 1).
    ZeroRoutingOrder,
}

impl fmt::Display for RecipientValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEmail => f.write_str("email must not be empty"),
            Self::InvalidEmailFormat => f.write_str("email must contain '@'"),
            Self::EmptyName => f.write_str("name must not be empty"),
            Self::EmptyRecipientId => f.write_str("recipient_id must not be empty"),
            Self::ZeroRoutingOrder => f.write_str("routing_order must be >= 1"),
        }
    }
}

impl Recipient {
    /// Validate the recipient fields.
    ///
    /// Returns a list of validation errors (empty if valid).
    #[must_use]
    pub fn validate(&self) -> Vec<RecipientValidationError> {
        let mut errors = Vec::new();
        if self.email.is_empty() {
            errors.push(RecipientValidationError::EmptyEmail);
        } else if !self.email.contains('@') {
            errors.push(RecipientValidationError::InvalidEmailFormat);
        }
        if self.name.is_empty() {
            errors.push(RecipientValidationError::EmptyName);
        }
        if self.recipient_id.is_empty() {
            errors.push(RecipientValidationError::EmptyRecipientId);
        }
        if self.routing_order == 0 {
            errors.push(RecipientValidationError::ZeroRoutingOrder);
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// TabType
// ---------------------------------------------------------------------------

/// The type of tab (field) that can be placed on a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TabType {
    /// Signature field.
    SignHere,
    /// Initials field.
    InitialHere,
    /// Auto-populated date-signed field.
    DateSigned,
    /// Free-text input field.
    Text,
    /// Checkbox field.
    Checkbox,
    /// Radio button group.
    RadioGroup,
    /// Dropdown select field.
    Dropdown,
    /// Auto-populated company name.
    Company,
    /// Auto-populated title.
    Title,
    /// Auto-populated full name.
    FullName,
    /// Auto-populated email.
    Email,
    /// Numeric input field.
    Number,
    /// SSN input field.
    Ssn,
    /// ZIP code input field.
    Zip,
    /// Formula (calculated) field.
    Formula,
}

impl TabType {
    /// Returns the `DocuSign` API string for this tab type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SignHere => "signHere",
            Self::InitialHere => "initialHere",
            Self::DateSigned => "dateSigned",
            Self::Text => "text",
            Self::Checkbox => "checkbox",
            Self::RadioGroup => "radioGroup",
            Self::Dropdown => "dropdown",
            Self::Company => "company",
            Self::Title => "title",
            Self::FullName => "fullName",
            Self::Email => "email",
            Self::Number => "number",
            Self::Ssn => "ssn",
            Self::Zip => "zip",
            Self::Formula => "formula",
        }
    }

    /// Returns `true` if this tab type is automatically populated by `DocuSign`.
    #[must_use]
    pub const fn is_system_populated(&self) -> bool {
        matches!(
            self,
            Self::DateSigned | Self::Company | Self::Title | Self::FullName | Self::Email
        )
    }
}

impl fmt::Display for TabType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TabPlacement
// ---------------------------------------------------------------------------

/// How a tab is positioned on a document page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TabPlacement {
    /// Absolute coordinate placement on a specific page.
    Coordinate {
        /// 1-based page number.
        page: u32,
        /// X position in pixels from the left edge.
        x: u32,
        /// Y position in pixels from the top edge.
        y: u32,
    },
    /// Anchor string placement — `DocuSign` searches for the string and places
    /// the tab relative to its location.
    Anchor {
        /// The text string to search for in the document.
        anchor_string: String,
        /// Horizontal offset from the anchor in pixels.
        x_offset: i32,
        /// Vertical offset from the anchor in pixels.
        y_offset: i32,
        /// Optional page restriction.
        #[serde(skip_serializing_if = "Option::is_none")]
        page: Option<u32>,
    },
}

// ---------------------------------------------------------------------------
// TabValidationError
// ---------------------------------------------------------------------------

/// Errors from validating a [`Tab`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabValidationError {
    /// No placement was specified.
    MissingPlacement,
    /// Coordinate values are out of range.
    InvalidCoordinate,
    /// Anchor string is empty.
    EmptyAnchorString,
    /// Anchor string exceeds the maximum length.
    AnchorTooLong,
    /// Page number is zero (must be >= 1).
    InvalidPageNumber,
    /// Value exceeds the maximum length.
    ValueTooLong,
    /// A negative offset was supplied where only non-negative is allowed.
    NegativeOffset,
}

impl fmt::Display for TabValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPlacement => f.write_str("tab placement is required"),
            Self::InvalidCoordinate => f.write_str("coordinate values out of range"),
            Self::EmptyAnchorString => f.write_str("anchor string must not be empty"),
            Self::AnchorTooLong => f.write_str("anchor string exceeds maximum length"),
            Self::InvalidPageNumber => f.write_str("page number must be >= 1"),
            Self::ValueTooLong => f.write_str("value exceeds maximum length"),
            Self::NegativeOffset => f.write_str("negative offset not allowed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tab + TabBuilder
// ---------------------------------------------------------------------------

/// A tab (field) placed on a document for a recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tab {
    /// The kind of tab.
    pub tab_type: TabType,
    /// Where the tab is placed.
    pub placement: TabPlacement,
    /// Optional label for identification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tab_label: Option<String>,
    /// Optional pre-filled value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Whether the tab is required.
    pub required: bool,
    /// Whether the tab value is locked (read-only for the recipient).
    pub locked: bool,
    /// Optional width in pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// Optional height in pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Optional font size (e.g. `"size12"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<String>,
    /// Whether the text should be bold.
    pub bold: bool,
}

/// Builder for constructing a [`Tab`] with validation.
#[derive(Debug, Clone)]
pub struct TabBuilder {
    tab_type: TabType,
    placement: Option<TabPlacement>,
    tab_label: Option<String>,
    value: Option<String>,
    required: bool,
    locked: bool,
    width: Option<u32>,
    height: Option<u32>,
    font_size: Option<String>,
    bold: bool,
}

impl TabBuilder {
    /// Start building a new tab of the given type.
    #[must_use]
    pub const fn new(tab_type: TabType) -> Self {
        Self {
            tab_type,
            placement: None,
            tab_label: None,
            value: None,
            required: false,
            locked: false,
            width: None,
            height: None,
            font_size: None,
            bold: false,
        }
    }

    /// Place the tab at absolute coordinates.
    #[must_use]
    pub fn at_coordinate(mut self, page: u32, x: u32, y: u32) -> Self {
        self.placement = Some(TabPlacement::Coordinate { page, x, y });
        self
    }

    /// Place the tab using an anchor string.
    #[must_use]
    pub fn at_anchor(mut self, anchor_string: &str, x_offset: i32, y_offset: i32) -> Self {
        self.placement = Some(TabPlacement::Anchor {
            anchor_string: anchor_string.to_owned(),
            x_offset,
            y_offset,
            page: None,
        });
        self
    }

    /// Place the tab using an anchor string restricted to a specific page.
    #[must_use]
    pub fn at_anchor_on_page(
        mut self,
        anchor_string: &str,
        x_offset: i32,
        y_offset: i32,
        page: u32,
    ) -> Self {
        self.placement = Some(TabPlacement::Anchor {
            anchor_string: anchor_string.to_owned(),
            x_offset,
            y_offset,
            page: Some(page),
        });
        self
    }

    /// Set the tab label.
    #[must_use]
    pub fn with_label(mut self, label: &str) -> Self {
        self.tab_label = Some(label.to_owned());
        self
    }

    /// Set a pre-filled value.
    #[must_use]
    pub fn with_value(mut self, value: &str) -> Self {
        self.value = Some(value.to_owned());
        self
    }

    /// Mark the tab as required.
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Mark the tab as locked (read-only).
    #[must_use]
    pub const fn locked(mut self) -> Self {
        self.locked = true;
        self
    }

    /// Set the width and height in pixels.
    #[must_use]
    pub const fn with_size(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }

    /// Set the font size.
    #[must_use]
    pub fn with_font_size(mut self, size: &str) -> Self {
        self.font_size = Some(size.to_owned());
        self
    }

    /// Enable bold text.
    #[must_use]
    pub const fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Build the [`Tab`], returning an error if placement is missing.
    pub fn build(self) -> Result<Tab, TabValidationError> {
        let placement = self.placement.ok_or(TabValidationError::MissingPlacement)?;
        Ok(Tab {
            tab_type: self.tab_type,
            placement,
            tab_label: self.tab_label,
            value: self.value,
            required: self.required,
            locked: self.locked,
            width: self.width,
            height: self.height,
            font_size: self.font_size,
            bold: self.bold,
        })
    }
}

// ---------------------------------------------------------------------------
// RecipientTabs
// ---------------------------------------------------------------------------

/// A collection of tabs assigned to a specific recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientTabs {
    /// The recipient these tabs belong to.
    pub recipient_id: String,
    /// The tabs for this recipient.
    pub tabs: Vec<Tab>,
}

impl RecipientTabs {
    /// Create a new empty tab collection for the given recipient.
    #[must_use]
    pub fn new(recipient_id: &str) -> Self {
        Self {
            recipient_id: recipient_id.to_owned(),
            tabs: Vec::new(),
        }
    }

    /// Add a tab.
    pub fn add_tab(&mut self, tab: Tab) {
        self.tabs.push(tab);
    }

    /// Returns the number of tabs.
    #[must_use]
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    /// Returns `true` if any tab is a signature field.
    #[must_use]
    pub fn has_signature(&self) -> bool {
        self.tabs.iter().any(|t| t.tab_type == TabType::SignHere)
    }

    /// Returns `true` if any tab is an initials field.
    #[must_use]
    pub fn has_initials(&self) -> bool {
        self.tabs
            .iter()
            .any(|t| t.tab_type == TabType::InitialHere)
    }
}

// ---------------------------------------------------------------------------
// EnvelopeRecipients
// ---------------------------------------------------------------------------

/// A recipient paired with their tabs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientEntry {
    /// The recipient.
    pub recipient: Recipient,
    /// Tabs assigned to this recipient.
    pub tabs: RecipientTabs,
}

/// Manages all recipients and their tabs for a `DocuSign` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeRecipients {
    /// All recipient entries.
    pub recipients: Vec<RecipientEntry>,
}

impl Default for EnvelopeRecipients {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvelopeRecipients {
    /// Create an empty recipients collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recipients: Vec::new(),
        }
    }

    /// Add a recipient (with an empty tab collection).
    pub fn add_recipient(&mut self, recipient: Recipient) {
        let tabs = RecipientTabs::new(&recipient.recipient_id);
        self.recipients.push(RecipientEntry { recipient, tabs });
    }

    /// Add a tab to an existing recipient by `recipient_id`.
    ///
    /// Returns `true` if the recipient was found, `false` otherwise.
    pub fn add_tab_to_recipient(&mut self, recipient_id: &str, tab: Tab) -> bool {
        for entry in &mut self.recipients {
            if entry.recipient.recipient_id == recipient_id {
                entry.tabs.add_tab(tab);
                return true;
            }
        }
        false
    }

    /// Validate all recipients and return any errors keyed by recipient id.
    #[must_use]
    pub fn validate_all(&self) -> Vec<(String, Vec<RecipientValidationError>)> {
        let mut result = Vec::new();
        for entry in &self.recipients {
            let errors = entry.recipient.validate();
            if !errors.is_empty() {
                result.push((entry.recipient.recipient_id.clone(), errors));
            }
        }
        result
    }

    /// Count the number of signers (role = Signer or `InPersonSigner`).
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.recipients
            .iter()
            .filter(|e| e.recipient.role.requires_signature())
            .count()
    }

    /// Returns `true` if the routing order across recipients is valid.
    ///
    /// Routing order is valid when all routing orders are >= 1 and there are
    /// no gaps (every value from 1 to max must be present).
    #[must_use]
    pub fn has_valid_routing(&self) -> bool {
        if self.recipients.is_empty() {
            return true;
        }
        let mut orders: Vec<u32> = self
            .recipients
            .iter()
            .map(|e| e.recipient.routing_order)
            .collect();
        orders.sort_unstable();
        // All must be >= 1
        if orders[0] == 0 {
            return false;
        }
        // Check for contiguous sequence starting at 1
        // Duplicates are allowed (parallel routing)
        orders.dedup();
        for (i, &order) in orders.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let expected = (i as u32) + 1;
            if order != expected {
                return false;
            }
        }
        true
    }

    /// Total number of recipients.
    #[must_use]
    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Total number of tabs across all recipients.
    #[must_use]
    pub fn total_tab_count(&self) -> usize {
        self.recipients.iter().map(|e| e.tabs.tab_count()).sum()
    }
}

// ---------------------------------------------------------------------------
// RecipientsValidator
// ---------------------------------------------------------------------------

/// Configurable validator for recipients and tabs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientsValidator {
    /// Maximum number of recipients allowed.
    pub max_recipients: usize,
    /// Maximum number of tabs per recipient.
    pub max_tabs_per_recipient: usize,
    /// Maximum length of an anchor string.
    pub max_anchor_length: usize,
    /// Maximum length of a tab value.
    pub max_value_length: usize,
}

impl Default for RecipientsValidator {
    fn default() -> Self {
        Self {
            max_recipients: 20,
            max_tabs_per_recipient: 200,
            max_anchor_length: 500,
            max_value_length: 4000,
        }
    }
}

/// Errors from the [`RecipientsValidator`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    /// A recipient-level error.
    Recipient {
        recipient_id: String,
        errors: Vec<RecipientValidationError>,
    },
    /// A tab-level error.
    Tab {
        recipient_id: String,
        tab_index: usize,
        error: TabValidationError,
    },
    /// Too many recipients.
    TooManyRecipients { count: usize, max: usize },
    /// Too many tabs on a single recipient.
    TooManyTabs {
        recipient_id: String,
        count: usize,
        max: usize,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recipient {
                recipient_id,
                errors,
            } => {
                write!(f, "recipient {recipient_id}: ")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            Self::Tab {
                recipient_id,
                tab_index,
                error,
            } => write!(
                f,
                "recipient {recipient_id} tab {tab_index}: {error}"
            ),
            Self::TooManyRecipients { count, max } => {
                write!(f, "too many recipients: {count} (max {max})")
            }
            Self::TooManyTabs {
                recipient_id,
                count,
                max,
            } => write!(
                f,
                "recipient {recipient_id}: too many tabs {count} (max {max})"
            ),
        }
    }
}

impl RecipientsValidator {
    /// Create a new validator with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate a single recipient.
    #[must_use]
    pub fn validate_recipient(&self, recipient: &Recipient) -> Vec<RecipientValidationError> {
        recipient.validate()
    }

    /// Validate a single tab.
    #[must_use]
    pub fn validate_tab(&self, tab: &Tab) -> Vec<TabValidationError> {
        let mut errors = Vec::new();
        match &tab.placement {
            TabPlacement::Coordinate { page, .. } => {
                if *page == 0 {
                    errors.push(TabValidationError::InvalidPageNumber);
                }
            }
            TabPlacement::Anchor {
                anchor_string,
                page,
                ..
            } => {
                if anchor_string.is_empty() {
                    errors.push(TabValidationError::EmptyAnchorString);
                }
                if anchor_string.len() > self.max_anchor_length {
                    errors.push(TabValidationError::AnchorTooLong);
                }
                if let Some(p) = page {
                    if *p == 0 {
                        errors.push(TabValidationError::InvalidPageNumber);
                    }
                }
            }
        }
        if let Some(val) = &tab.value {
            if val.len() > self.max_value_length {
                errors.push(TabValidationError::ValueTooLong);
            }
        }
        errors
    }

    /// Validate an entire [`EnvelopeRecipients`] collection.
    #[must_use]
    pub fn validate_all(&self, envelope: &EnvelopeRecipients) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if envelope.recipients.len() > self.max_recipients {
            errors.push(ValidationError::TooManyRecipients {
                count: envelope.recipients.len(),
                max: self.max_recipients,
            });
        }

        for entry in &envelope.recipients {
            let r_errors = self.validate_recipient(&entry.recipient);
            if !r_errors.is_empty() {
                errors.push(ValidationError::Recipient {
                    recipient_id: entry.recipient.recipient_id.clone(),
                    errors: r_errors,
                });
            }

            if entry.tabs.tab_count() > self.max_tabs_per_recipient {
                errors.push(ValidationError::TooManyTabs {
                    recipient_id: entry.recipient.recipient_id.clone(),
                    count: entry.tabs.tab_count(),
                    max: self.max_tabs_per_recipient,
                });
            }

            for (i, tab) in entry.tabs.tabs.iter().enumerate() {
                let t_errors = self.validate_tab(tab);
                for err in t_errors {
                    errors.push(ValidationError::Tab {
                        recipient_id: entry.recipient.recipient_id.clone(),
                        tab_index: i,
                        error: err,
                    });
                }
            }
        }

        errors
    }
}

// ---------------------------------------------------------------------------
// RecipientsAuditEvent
// ---------------------------------------------------------------------------

/// Audit event for recipient/tab operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientsAuditEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Description of the action performed.
    pub action: String,
    /// Number of recipients at the time of the event.
    pub recipient_count: usize,
    /// Total number of tabs at the time of the event.
    pub tab_count: usize,
}

impl RecipientsAuditEvent {
    /// Create a new audit event.
    #[must_use]
    pub fn new(
        timestamp: &str,
        action: &str,
        recipient_count: usize,
        tab_count: usize,
    ) -> Self {
        Self {
            timestamp: timestamp.to_owned(),
            action: action.to_owned(),
            recipient_count,
            tab_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper ---

    fn make_recipient(id: &str, role: RecipientRole, order: u32) -> Recipient {
        Recipient {
            email: format!("{id}@example.com"),
            name: id.to_uppercase(),
            role,
            recipient_id: id.to_owned(),
            routing_order: order,
            access_code: None,
            id_check: None,
        }
    }

    fn make_sign_tab(page: u32, x: u32, y: u32) -> Tab {
        TabBuilder::new(TabType::SignHere)
            .at_coordinate(page, x, y)
            .build()
            .unwrap()
    }

    fn make_anchor_tab(anchor: &str) -> Tab {
        TabBuilder::new(TabType::Text)
            .at_anchor(anchor, 10, 20)
            .build()
            .unwrap()
    }

    // ===================================================================
    // RecipientRole
    // ===================================================================

    #[test]
    fn role_as_str_signer() {
        assert_eq!(RecipientRole::Signer.as_str(), "signer");
    }

    #[test]
    fn role_as_str_carbon_copy() {
        assert_eq!(RecipientRole::CarbonCopy.as_str(), "carbonCopy");
    }

    #[test]
    fn role_as_str_certified_delivery() {
        assert_eq!(RecipientRole::CertifiedDelivery.as_str(), "certifiedDelivery");
    }

    #[test]
    fn role_as_str_in_person_signer() {
        assert_eq!(RecipientRole::InPersonSigner.as_str(), "inPersonSigner");
    }

    #[test]
    fn role_as_str_editor() {
        assert_eq!(RecipientRole::Editor.as_str(), "editor");
    }

    #[test]
    fn role_as_str_agent() {
        assert_eq!(RecipientRole::Agent.as_str(), "agent");
    }

    #[test]
    fn role_as_str_intermediary() {
        assert_eq!(RecipientRole::Intermediary.as_str(), "intermediary");
    }

    #[test]
    fn role_as_str_seal() {
        assert_eq!(RecipientRole::Seal.as_str(), "seal");
    }

    #[test]
    fn role_requires_signature_signer() {
        assert!(RecipientRole::Signer.requires_signature());
    }

    #[test]
    fn role_requires_signature_in_person() {
        assert!(RecipientRole::InPersonSigner.requires_signature());
    }

    #[test]
    fn role_no_signature_carbon_copy() {
        assert!(!RecipientRole::CarbonCopy.requires_signature());
    }

    #[test]
    fn role_no_signature_editor() {
        assert!(!RecipientRole::Editor.requires_signature());
    }

    #[test]
    fn role_no_signature_agent() {
        assert!(!RecipientRole::Agent.requires_signature());
    }

    #[test]
    fn role_no_signature_intermediary() {
        assert!(!RecipientRole::Intermediary.requires_signature());
    }

    #[test]
    fn role_no_signature_seal() {
        assert!(!RecipientRole::Seal.requires_signature());
    }

    #[test]
    fn role_no_signature_certified_delivery() {
        assert!(!RecipientRole::CertifiedDelivery.requires_signature());
    }

    #[test]
    fn role_display() {
        assert_eq!(format!("{}", RecipientRole::Signer), "signer");
        assert_eq!(format!("{}", RecipientRole::CarbonCopy), "carbonCopy");
    }

    #[test]
    fn role_debug() {
        let dbg = format!("{:?}", RecipientRole::Signer);
        assert!(dbg.contains("Signer"));
    }

    #[test]
    fn role_clone() {
        let r = RecipientRole::Signer;
        let cloned = r;
        assert_eq!(r, cloned);
    }

    #[test]
    fn role_eq() {
        assert_eq!(RecipientRole::Signer, RecipientRole::Signer);
        assert_ne!(RecipientRole::Signer, RecipientRole::CarbonCopy);
    }

    #[test]
    fn role_serde_roundtrip() {
        let r = RecipientRole::CertifiedDelivery;
        let json = serde_json::to_string(&r).unwrap();
        let back: RecipientRole = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ===================================================================
    // Recipient validation
    // ===================================================================

    #[test]
    fn recipient_valid() {
        let r = make_recipient("1", RecipientRole::Signer, 1);
        assert!(r.validate().is_empty());
    }

    #[test]
    fn recipient_empty_email() {
        let mut r = make_recipient("1", RecipientRole::Signer, 1);
        r.email = String::new();
        let errors = r.validate();
        assert!(errors.contains(&RecipientValidationError::EmptyEmail));
    }

    #[test]
    fn recipient_invalid_email_no_at() {
        let mut r = make_recipient("1", RecipientRole::Signer, 1);
        r.email = "bademail".into();
        let errors = r.validate();
        assert!(errors.contains(&RecipientValidationError::InvalidEmailFormat));
    }

    #[test]
    fn recipient_empty_name() {
        let mut r = make_recipient("1", RecipientRole::Signer, 1);
        r.name = String::new();
        let errors = r.validate();
        assert!(errors.contains(&RecipientValidationError::EmptyName));
    }

    #[test]
    fn recipient_empty_recipient_id() {
        let mut r = make_recipient("", RecipientRole::Signer, 1);
        r.recipient_id = String::new();
        let errors = r.validate();
        assert!(errors.contains(&RecipientValidationError::EmptyRecipientId));
    }

    #[test]
    fn recipient_zero_routing_order() {
        let r = make_recipient("1", RecipientRole::Signer, 0);
        let errors = r.validate();
        assert!(errors.contains(&RecipientValidationError::ZeroRoutingOrder));
    }

    #[test]
    fn recipient_multiple_errors() {
        let r = Recipient {
            email: String::new(),
            name: String::new(),
            role: RecipientRole::Signer,
            recipient_id: String::new(),
            routing_order: 0,
            access_code: None,
            id_check: None,
        };
        let errors = r.validate();
        assert!(errors.len() >= 4);
    }

    #[test]
    fn recipient_with_access_code() {
        let mut r = make_recipient("1", RecipientRole::Signer, 1);
        r.access_code = Some("1234".into());
        assert!(r.validate().is_empty());
    }

    #[test]
    fn recipient_with_id_check() {
        let mut r = make_recipient("1", RecipientRole::Signer, 1);
        r.id_check = Some(true);
        assert!(r.validate().is_empty());
    }

    #[test]
    fn recipient_serde_roundtrip() {
        let r = make_recipient("1", RecipientRole::Signer, 1);
        let json = serde_json::to_value(&r).unwrap();
        let back: Recipient = serde_json::from_value(json).unwrap();
        assert_eq!(back.email, r.email);
        assert_eq!(back.name, r.name);
        assert_eq!(back.recipient_id, r.recipient_id);
    }

    #[test]
    fn recipient_debug() {
        let r = make_recipient("1", RecipientRole::Signer, 1);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Recipient"));
    }

    #[test]
    fn recipient_clone_independence() {
        let r = make_recipient("1", RecipientRole::Signer, 1);
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.recipient_id, "1");
    }

    #[test]
    fn recipient_validation_error_display() {
        assert_eq!(RecipientValidationError::EmptyEmail.to_string(), "email must not be empty");
        assert_eq!(RecipientValidationError::InvalidEmailFormat.to_string(), "email must contain '@'");
        assert_eq!(RecipientValidationError::EmptyName.to_string(), "name must not be empty");
        assert_eq!(RecipientValidationError::EmptyRecipientId.to_string(), "recipient_id must not be empty");
        assert_eq!(RecipientValidationError::ZeroRoutingOrder.to_string(), "routing_order must be >= 1");
    }

    // ===================================================================
    // TabType
    // ===================================================================

    #[test]
    fn tab_type_as_str_sign_here() {
        assert_eq!(TabType::SignHere.as_str(), "signHere");
    }

    #[test]
    fn tab_type_as_str_initial_here() {
        assert_eq!(TabType::InitialHere.as_str(), "initialHere");
    }

    #[test]
    fn tab_type_as_str_date_signed() {
        assert_eq!(TabType::DateSigned.as_str(), "dateSigned");
    }

    #[test]
    fn tab_type_as_str_text() {
        assert_eq!(TabType::Text.as_str(), "text");
    }

    #[test]
    fn tab_type_as_str_checkbox() {
        assert_eq!(TabType::Checkbox.as_str(), "checkbox");
    }

    #[test]
    fn tab_type_as_str_radio_group() {
        assert_eq!(TabType::RadioGroup.as_str(), "radioGroup");
    }

    #[test]
    fn tab_type_as_str_dropdown() {
        assert_eq!(TabType::Dropdown.as_str(), "dropdown");
    }

    #[test]
    fn tab_type_as_str_company() {
        assert_eq!(TabType::Company.as_str(), "company");
    }

    #[test]
    fn tab_type_as_str_title() {
        assert_eq!(TabType::Title.as_str(), "title");
    }

    #[test]
    fn tab_type_as_str_full_name() {
        assert_eq!(TabType::FullName.as_str(), "fullName");
    }

    #[test]
    fn tab_type_as_str_email() {
        assert_eq!(TabType::Email.as_str(), "email");
    }

    #[test]
    fn tab_type_as_str_number() {
        assert_eq!(TabType::Number.as_str(), "number");
    }

    #[test]
    fn tab_type_as_str_ssn() {
        assert_eq!(TabType::Ssn.as_str(), "ssn");
    }

    #[test]
    fn tab_type_as_str_zip() {
        assert_eq!(TabType::Zip.as_str(), "zip");
    }

    #[test]
    fn tab_type_as_str_formula() {
        assert_eq!(TabType::Formula.as_str(), "formula");
    }

    #[test]
    fn tab_type_system_populated_date_signed() {
        assert!(TabType::DateSigned.is_system_populated());
    }

    #[test]
    fn tab_type_system_populated_company() {
        assert!(TabType::Company.is_system_populated());
    }

    #[test]
    fn tab_type_system_populated_title() {
        assert!(TabType::Title.is_system_populated());
    }

    #[test]
    fn tab_type_system_populated_full_name() {
        assert!(TabType::FullName.is_system_populated());
    }

    #[test]
    fn tab_type_system_populated_email() {
        assert!(TabType::Email.is_system_populated());
    }

    #[test]
    fn tab_type_not_system_populated_sign_here() {
        assert!(!TabType::SignHere.is_system_populated());
    }

    #[test]
    fn tab_type_not_system_populated_text() {
        assert!(!TabType::Text.is_system_populated());
    }

    #[test]
    fn tab_type_not_system_populated_checkbox() {
        assert!(!TabType::Checkbox.is_system_populated());
    }

    #[test]
    fn tab_type_not_system_populated_number() {
        assert!(!TabType::Number.is_system_populated());
    }

    #[test]
    fn tab_type_not_system_populated_formula() {
        assert!(!TabType::Formula.is_system_populated());
    }

    #[test]
    fn tab_type_display() {
        assert_eq!(format!("{}", TabType::SignHere), "signHere");
        assert_eq!(format!("{}", TabType::Text), "text");
    }

    #[test]
    fn tab_type_serde_roundtrip() {
        let t = TabType::RadioGroup;
        let json = serde_json::to_string(&t).unwrap();
        let back: TabType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn tab_type_eq() {
        assert_eq!(TabType::SignHere, TabType::SignHere);
        assert_ne!(TabType::SignHere, TabType::Text);
    }

    // ===================================================================
    // TabPlacement
    // ===================================================================

    #[test]
    fn placement_coordinate_debug() {
        let p = TabPlacement::Coordinate { page: 1, x: 100, y: 200 };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Coordinate"));
    }

    #[test]
    fn placement_anchor_debug() {
        let p = TabPlacement::Anchor {
            anchor_string: "Sign:".into(),
            x_offset: 10,
            y_offset: 20,
            page: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Anchor"));
    }

    #[test]
    fn placement_coordinate_eq() {
        let a = TabPlacement::Coordinate { page: 1, x: 50, y: 60 };
        let b = TabPlacement::Coordinate { page: 1, x: 50, y: 60 };
        assert_eq!(a, b);
    }

    #[test]
    fn placement_coordinate_ne() {
        let a = TabPlacement::Coordinate { page: 1, x: 50, y: 60 };
        let b = TabPlacement::Coordinate { page: 2, x: 50, y: 60 };
        assert_ne!(a, b);
    }

    #[test]
    fn placement_anchor_eq() {
        let a = TabPlacement::Anchor {
            anchor_string: "Sign:".into(),
            x_offset: 0,
            y_offset: 0,
            page: None,
        };
        let b = TabPlacement::Anchor {
            anchor_string: "Sign:".into(),
            x_offset: 0,
            y_offset: 0,
            page: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn placement_serde_roundtrip_coordinate() {
        let p = TabPlacement::Coordinate { page: 3, x: 150, y: 300 };
        let json = serde_json::to_value(&p).unwrap();
        let back: TabPlacement = serde_json::from_value(json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn placement_serde_roundtrip_anchor() {
        let p = TabPlacement::Anchor {
            anchor_string: "Signature:".into(),
            x_offset: -5,
            y_offset: 10,
            page: Some(2),
        };
        let json = serde_json::to_value(&p).unwrap();
        let back: TabPlacement = serde_json::from_value(json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn placement_clone() {
        let p = TabPlacement::Coordinate { page: 1, x: 10, y: 20 };
        let cloned = p.clone();
        assert_eq!(p, cloned);
    }

    // ===================================================================
    // TabBuilder + Tab
    // ===================================================================

    #[test]
    fn builder_coordinate_tab() {
        let tab = TabBuilder::new(TabType::SignHere)
            .at_coordinate(1, 100, 200)
            .build()
            .unwrap();
        assert_eq!(tab.tab_type, TabType::SignHere);
        assert_eq!(tab.placement, TabPlacement::Coordinate { page: 1, x: 100, y: 200 });
        assert!(!tab.required);
        assert!(!tab.locked);
        assert!(!tab.bold);
    }

    #[test]
    fn builder_anchor_tab() {
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor("Sign here:", 5, -10)
            .build()
            .unwrap();
        match &tab.placement {
            TabPlacement::Anchor { anchor_string, x_offset, y_offset, page } => {
                assert_eq!(anchor_string, "Sign here:");
                assert_eq!(*x_offset, 5);
                assert_eq!(*y_offset, -10);
                assert!(page.is_none());
            }
            TabPlacement::Coordinate { .. } => panic!("expected Anchor placement"),
        }
    }

    #[test]
    fn builder_anchor_on_page() {
        let tab = TabBuilder::new(TabType::InitialHere)
            .at_anchor_on_page("Init:", 0, 0, 3)
            .build()
            .unwrap();
        match &tab.placement {
            TabPlacement::Anchor { page, .. } => assert_eq!(*page, Some(3)),
            TabPlacement::Coordinate { .. } => panic!("expected Anchor placement"),
        }
    }

    #[test]
    fn builder_missing_placement() {
        let err = TabBuilder::new(TabType::SignHere).build().unwrap_err();
        assert_eq!(err, TabValidationError::MissingPlacement);
    }

    #[test]
    fn builder_with_label() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .with_label("field_1")
            .build()
            .unwrap();
        assert_eq!(tab.tab_label, Some("field_1".into()));
    }

    #[test]
    fn builder_with_value() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .with_value("Hello")
            .build()
            .unwrap();
        assert_eq!(tab.value, Some("Hello".into()));
    }

    #[test]
    fn builder_required() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .required()
            .build()
            .unwrap();
        assert!(tab.required);
    }

    #[test]
    fn builder_locked() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .locked()
            .build()
            .unwrap();
        assert!(tab.locked);
    }

    #[test]
    fn builder_with_size() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .with_size(200, 50)
            .build()
            .unwrap();
        assert_eq!(tab.width, Some(200));
        assert_eq!(tab.height, Some(50));
    }

    #[test]
    fn builder_with_font_size() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .with_font_size("size14")
            .build()
            .unwrap();
        assert_eq!(tab.font_size, Some("size14".into()));
    }

    #[test]
    fn builder_bold() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .bold()
            .build()
            .unwrap();
        assert!(tab.bold);
    }

    #[test]
    fn builder_full_chain() {
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(2, 300, 400)
            .with_label("address")
            .with_value("123 Main St")
            .required()
            .locked()
            .with_size(250, 30)
            .with_font_size("size12")
            .bold()
            .build()
            .unwrap();
        assert_eq!(tab.tab_type, TabType::Text);
        assert_eq!(tab.tab_label, Some("address".into()));
        assert_eq!(tab.value, Some("123 Main St".into()));
        assert!(tab.required);
        assert!(tab.locked);
        assert_eq!(tab.width, Some(250));
        assert_eq!(tab.height, Some(30));
        assert_eq!(tab.font_size, Some("size12".into()));
        assert!(tab.bold);
    }

    #[test]
    fn tab_serde_roundtrip() {
        let tab = make_sign_tab(1, 100, 200);
        let json = serde_json::to_value(&tab).unwrap();
        let back: Tab = serde_json::from_value(json).unwrap();
        assert_eq!(back.tab_type, TabType::SignHere);
    }

    #[test]
    fn tab_debug() {
        let tab = make_sign_tab(1, 10, 20);
        let dbg = format!("{tab:?}");
        assert!(dbg.contains("Tab"));
    }

    #[test]
    fn tab_clone_independence() {
        let tab = make_sign_tab(1, 10, 20);
        let cloned = tab.clone();
        drop(tab);
        assert_eq!(cloned.tab_type, TabType::SignHere);
    }

    #[test]
    fn tab_defaults_not_required() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(!tab.required);
    }

    #[test]
    fn tab_defaults_not_locked() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(!tab.locked);
    }

    #[test]
    fn tab_defaults_not_bold() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(!tab.bold);
    }

    #[test]
    fn tab_defaults_no_label() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(tab.tab_label.is_none());
    }

    #[test]
    fn tab_defaults_no_value() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(tab.value.is_none());
    }

    #[test]
    fn tab_defaults_no_size() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(tab.width.is_none());
        assert!(tab.height.is_none());
    }

    #[test]
    fn tab_defaults_no_font_size() {
        let tab = make_sign_tab(1, 10, 20);
        assert!(tab.font_size.is_none());
    }

    // ===================================================================
    // TabValidationError
    // ===================================================================

    #[test]
    fn tab_validation_error_display_missing_placement() {
        assert_eq!(TabValidationError::MissingPlacement.to_string(), "tab placement is required");
    }

    #[test]
    fn tab_validation_error_display_invalid_coordinate() {
        assert_eq!(TabValidationError::InvalidCoordinate.to_string(), "coordinate values out of range");
    }

    #[test]
    fn tab_validation_error_display_empty_anchor() {
        assert_eq!(TabValidationError::EmptyAnchorString.to_string(), "anchor string must not be empty");
    }

    #[test]
    fn tab_validation_error_display_anchor_too_long() {
        assert_eq!(TabValidationError::AnchorTooLong.to_string(), "anchor string exceeds maximum length");
    }

    #[test]
    fn tab_validation_error_display_invalid_page() {
        assert_eq!(TabValidationError::InvalidPageNumber.to_string(), "page number must be >= 1");
    }

    #[test]
    fn tab_validation_error_display_value_too_long() {
        assert_eq!(TabValidationError::ValueTooLong.to_string(), "value exceeds maximum length");
    }

    #[test]
    fn tab_validation_error_display_negative_offset() {
        assert_eq!(TabValidationError::NegativeOffset.to_string(), "negative offset not allowed");
    }

    #[test]
    fn tab_validation_error_eq() {
        assert_eq!(TabValidationError::MissingPlacement, TabValidationError::MissingPlacement);
        assert_ne!(TabValidationError::MissingPlacement, TabValidationError::EmptyAnchorString);
    }

    #[test]
    fn tab_validation_error_serde_roundtrip() {
        let e = TabValidationError::AnchorTooLong;
        let json = serde_json::to_string(&e).unwrap();
        let back: TabValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // ===================================================================
    // RecipientTabs
    // ===================================================================

    #[test]
    fn recipient_tabs_new_empty() {
        let tabs = RecipientTabs::new("1");
        assert_eq!(tabs.recipient_id, "1");
        assert_eq!(tabs.tab_count(), 0);
    }

    #[test]
    fn recipient_tabs_add_tab() {
        let mut tabs = RecipientTabs::new("1");
        tabs.add_tab(make_sign_tab(1, 100, 200));
        assert_eq!(tabs.tab_count(), 1);
    }

    #[test]
    fn recipient_tabs_has_signature() {
        let mut tabs = RecipientTabs::new("1");
        assert!(!tabs.has_signature());
        tabs.add_tab(make_sign_tab(1, 100, 200));
        assert!(tabs.has_signature());
    }

    #[test]
    fn recipient_tabs_has_initials() {
        let mut tabs = RecipientTabs::new("1");
        assert!(!tabs.has_initials());
        let initials = TabBuilder::new(TabType::InitialHere)
            .at_coordinate(1, 50, 50)
            .build()
            .unwrap();
        tabs.add_tab(initials);
        assert!(tabs.has_initials());
    }

    #[test]
    fn recipient_tabs_no_signature_for_text() {
        let mut tabs = RecipientTabs::new("1");
        tabs.add_tab(make_anchor_tab("field"));
        assert!(!tabs.has_signature());
    }

    #[test]
    fn recipient_tabs_multiple() {
        let mut tabs = RecipientTabs::new("1");
        tabs.add_tab(make_sign_tab(1, 100, 200));
        tabs.add_tab(make_sign_tab(1, 100, 400));
        tabs.add_tab(make_anchor_tab("Date:"));
        assert_eq!(tabs.tab_count(), 3);
    }

    #[test]
    fn recipient_tabs_serde_roundtrip() {
        let mut tabs = RecipientTabs::new("1");
        tabs.add_tab(make_sign_tab(1, 100, 200));
        let json = serde_json::to_value(&tabs).unwrap();
        let back: RecipientTabs = serde_json::from_value(json).unwrap();
        assert_eq!(back.recipient_id, "1");
        assert_eq!(back.tab_count(), 1);
    }

    #[test]
    fn recipient_tabs_debug() {
        let tabs = RecipientTabs::new("1");
        let dbg = format!("{tabs:?}");
        assert!(dbg.contains("RecipientTabs"));
    }

    #[test]
    fn recipient_tabs_clone() {
        let mut tabs = RecipientTabs::new("1");
        tabs.add_tab(make_sign_tab(1, 10, 20));
        let cloned = tabs.clone();
        drop(tabs);
        assert_eq!(cloned.tab_count(), 1);
    }

    // ===================================================================
    // EnvelopeRecipients
    // ===================================================================

    #[test]
    fn envelope_recipients_new_empty() {
        let er = EnvelopeRecipients::new();
        assert_eq!(er.recipient_count(), 0);
        assert_eq!(er.total_tab_count(), 0);
    }

    #[test]
    fn envelope_recipients_default() {
        let er = EnvelopeRecipients::default();
        assert_eq!(er.recipient_count(), 0);
    }

    #[test]
    fn envelope_recipients_add_recipient() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        assert_eq!(er.recipient_count(), 1);
    }

    #[test]
    fn envelope_recipients_add_tab_to_recipient() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        let added = er.add_tab_to_recipient("1", make_sign_tab(1, 100, 200));
        assert!(added);
        assert_eq!(er.total_tab_count(), 1);
    }

    #[test]
    fn envelope_recipients_add_tab_unknown_recipient() {
        let mut er = EnvelopeRecipients::new();
        let added = er.add_tab_to_recipient("999", make_sign_tab(1, 100, 200));
        assert!(!added);
    }

    #[test]
    fn envelope_recipients_signer_count() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 2));
        er.add_recipient(make_recipient("3", RecipientRole::InPersonSigner, 2));
        assert_eq!(er.signer_count(), 2);
    }

    #[test]
    fn envelope_recipients_signer_count_none() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::CarbonCopy, 1));
        assert_eq!(er.signer_count(), 0);
    }

    #[test]
    fn envelope_recipients_validate_all_clean() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        let errors = er.validate_all();
        assert!(errors.is_empty());
    }

    #[test]
    fn envelope_recipients_validate_all_with_errors() {
        let mut er = EnvelopeRecipients::new();
        let mut bad = make_recipient("1", RecipientRole::Signer, 1);
        bad.email = String::new();
        er.add_recipient(bad);
        let errors = er.validate_all();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "1");
    }

    #[test]
    fn envelope_recipients_valid_routing_empty() {
        let er = EnvelopeRecipients::new();
        assert!(er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_valid_routing_single() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        assert!(er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_valid_routing_sequential() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 2));
        er.add_recipient(make_recipient("3", RecipientRole::Editor, 3));
        assert!(er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_valid_routing_parallel() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("3", RecipientRole::CarbonCopy, 2));
        assert!(er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_invalid_routing_gap() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 3));
        assert!(!er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_invalid_routing_zero() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 0));
        assert!(!er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_invalid_routing_starts_at_two() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 2));
        assert!(!er.has_valid_routing());
    }

    #[test]
    fn envelope_recipients_total_tab_count() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 2));
        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 200));
        er.add_tab_to_recipient("1", make_anchor_tab("Date:"));
        er.add_tab_to_recipient("2", make_anchor_tab("CC:"));
        assert_eq!(er.total_tab_count(), 3);
    }

    #[test]
    fn envelope_recipients_serde_roundtrip() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 200));
        let json = serde_json::to_value(&er).unwrap();
        let back: EnvelopeRecipients = serde_json::from_value(json).unwrap();
        assert_eq!(back.recipient_count(), 1);
        assert_eq!(back.total_tab_count(), 1);
    }

    #[test]
    fn envelope_recipients_debug() {
        let er = EnvelopeRecipients::new();
        let dbg = format!("{er:?}");
        assert!(dbg.contains("EnvelopeRecipients"));
    }

    #[test]
    fn envelope_recipients_clone() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        let cloned = er.clone();
        drop(er);
        assert_eq!(cloned.recipient_count(), 1);
    }

    // ===================================================================
    // RecipientsValidator
    // ===================================================================

    #[test]
    fn validator_default_limits() {
        let v = RecipientsValidator::new();
        assert_eq!(v.max_recipients, 20);
        assert_eq!(v.max_tabs_per_recipient, 200);
        assert_eq!(v.max_anchor_length, 500);
        assert_eq!(v.max_value_length, 4000);
    }

    #[test]
    fn validator_validate_recipient_ok() {
        let v = RecipientsValidator::new();
        let r = make_recipient("1", RecipientRole::Signer, 1);
        assert!(v.validate_recipient(&r).is_empty());
    }

    #[test]
    fn validator_validate_recipient_errors() {
        let v = RecipientsValidator::new();
        let mut r = make_recipient("1", RecipientRole::Signer, 1);
        r.email = String::new();
        let errors = v.validate_recipient(&r);
        assert!(!errors.is_empty());
    }

    #[test]
    fn validator_validate_tab_coordinate_ok() {
        let v = RecipientsValidator::new();
        let tab = make_sign_tab(1, 100, 200);
        assert!(v.validate_tab(&tab).is_empty());
    }

    #[test]
    fn validator_validate_tab_coordinate_page_zero() {
        let v = RecipientsValidator::new();
        let tab = make_sign_tab(0, 100, 200);
        let errors = v.validate_tab(&tab);
        assert!(errors.contains(&TabValidationError::InvalidPageNumber));
    }

    #[test]
    fn validator_validate_tab_anchor_ok() {
        let v = RecipientsValidator::new();
        let tab = make_anchor_tab("Sign here:");
        assert!(v.validate_tab(&tab).is_empty());
    }

    #[test]
    fn validator_validate_tab_anchor_empty() {
        let v = RecipientsValidator::new();
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor("", 0, 0)
            .build()
            .unwrap();
        let errors = v.validate_tab(&tab);
        assert!(errors.contains(&TabValidationError::EmptyAnchorString));
    }

    #[test]
    fn validator_validate_tab_anchor_too_long() {
        let v = RecipientsValidator {
            max_anchor_length: 10,
            ..RecipientsValidator::default()
        };
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor("this is a very long anchor string", 0, 0)
            .build()
            .unwrap();
        let errors = v.validate_tab(&tab);
        assert!(errors.contains(&TabValidationError::AnchorTooLong));
    }

    #[test]
    fn validator_validate_tab_anchor_page_zero() {
        let v = RecipientsValidator::new();
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor_on_page("X", 0, 0, 0)
            .build()
            .unwrap();
        let errors = v.validate_tab(&tab);
        assert!(errors.contains(&TabValidationError::InvalidPageNumber));
    }

    #[test]
    fn validator_validate_tab_value_too_long() {
        let v = RecipientsValidator {
            max_value_length: 5,
            ..RecipientsValidator::default()
        };
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .with_value("this is too long")
            .build()
            .unwrap();
        let errors = v.validate_tab(&tab);
        assert!(errors.contains(&TabValidationError::ValueTooLong));
    }

    #[test]
    fn validator_validate_all_clean() {
        let v = RecipientsValidator::new();
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 200));
        assert!(v.validate_all(&er).is_empty());
    }

    #[test]
    fn validator_validate_all_too_many_recipients() {
        let v = RecipientsValidator {
            max_recipients: 2,
            ..RecipientsValidator::default()
        };
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 2));
        er.add_recipient(make_recipient("3", RecipientRole::Editor, 3));
        let errors = v.validate_all(&er);
        assert!(errors.iter().any(|e| matches!(e, ValidationError::TooManyRecipients { .. })));
    }

    #[test]
    fn validator_validate_all_too_many_tabs() {
        let v = RecipientsValidator {
            max_tabs_per_recipient: 2,
            ..RecipientsValidator::default()
        };
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 100));
        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 200));
        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 300));
        let errors = v.validate_all(&er);
        assert!(errors.iter().any(|e| matches!(e, ValidationError::TooManyTabs { .. })));
    }

    #[test]
    fn validator_validate_all_recipient_and_tab_errors() {
        let v = RecipientsValidator::new();
        let mut er = EnvelopeRecipients::new();
        let mut bad = make_recipient("1", RecipientRole::Signer, 1);
        bad.email = String::new();
        er.add_recipient(bad);
        er.add_tab_to_recipient("1", make_sign_tab(0, 0, 0));
        let errors = v.validate_all(&er);
        assert!(errors.iter().any(|e| matches!(e, ValidationError::Recipient { .. })));
        assert!(errors.iter().any(|e| matches!(e, ValidationError::Tab { .. })));
    }

    #[test]
    fn validator_serde_roundtrip() {
        let v = RecipientsValidator::new();
        let json = serde_json::to_value(&v).unwrap();
        let back: RecipientsValidator = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_recipients, v.max_recipients);
    }

    #[test]
    fn validator_debug() {
        let v = RecipientsValidator::new();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("RecipientsValidator"));
    }

    #[test]
    fn validator_clone() {
        let v = RecipientsValidator::new();
        let cloned = v.clone();
        assert_eq!(cloned.max_recipients, v.max_recipients);
    }

    // ===================================================================
    // ValidationError display
    // ===================================================================

    #[test]
    fn validation_error_display_recipient() {
        let e = ValidationError::Recipient {
            recipient_id: "1".into(),
            errors: vec![RecipientValidationError::EmptyEmail],
        };
        let s = e.to_string();
        assert!(s.contains("recipient 1"));
        assert!(s.contains("email must not be empty"));
    }

    #[test]
    fn validation_error_display_tab() {
        let e = ValidationError::Tab {
            recipient_id: "2".into(),
            tab_index: 3,
            error: TabValidationError::EmptyAnchorString,
        };
        let s = e.to_string();
        assert!(s.contains("recipient 2"));
        assert!(s.contains("tab 3"));
    }

    #[test]
    fn validation_error_display_too_many_recipients() {
        let e = ValidationError::TooManyRecipients { count: 25, max: 20 };
        let s = e.to_string();
        assert!(s.contains("25"));
        assert!(s.contains("20"));
    }

    #[test]
    fn validation_error_display_too_many_tabs() {
        let e = ValidationError::TooManyTabs {
            recipient_id: "1".into(),
            count: 300,
            max: 200,
        };
        let s = e.to_string();
        assert!(s.contains("300"));
        assert!(s.contains("200"));
    }

    #[test]
    fn validation_error_display_multiple_recipient_errors() {
        let e = ValidationError::Recipient {
            recipient_id: "x".into(),
            errors: vec![
                RecipientValidationError::EmptyEmail,
                RecipientValidationError::EmptyName,
            ],
        };
        let s = e.to_string();
        assert!(s.contains("email must not be empty"));
        assert!(s.contains("name must not be empty"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let e = ValidationError::TooManyRecipients { count: 25, max: 20 };
        let json = serde_json::to_string(&e).unwrap();
        let back: ValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // ===================================================================
    // RecipientsAuditEvent
    // ===================================================================

    #[test]
    fn audit_event_new() {
        let e = RecipientsAuditEvent::new("2026-03-09T12:00:00Z", "add_recipient", 1, 0);
        assert_eq!(e.timestamp, "2026-03-09T12:00:00Z");
        assert_eq!(e.action, "add_recipient");
        assert_eq!(e.recipient_count, 1);
        assert_eq!(e.tab_count, 0);
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let e = RecipientsAuditEvent::new("2026-03-09T12:00:00Z", "add_tab", 2, 5);
        let json = serde_json::to_value(&e).unwrap();
        let back: RecipientsAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.action, "add_tab");
        assert_eq!(back.recipient_count, 2);
        assert_eq!(back.tab_count, 5);
    }

    #[test]
    fn audit_event_debug() {
        let e = RecipientsAuditEvent::new("2026-03-09T12:00:00Z", "test", 0, 0);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("RecipientsAuditEvent"));
    }

    #[test]
    fn audit_event_clone() {
        let e = RecipientsAuditEvent::new("2026-03-09T12:00:00Z", "test", 1, 2);
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.action, "test");
    }

    // ===================================================================
    // RecipientEntry
    // ===================================================================

    #[test]
    fn recipient_entry_serde_roundtrip() {
        let entry = RecipientEntry {
            recipient: make_recipient("1", RecipientRole::Signer, 1),
            tabs: RecipientTabs::new("1"),
        };
        let json = serde_json::to_value(&entry).unwrap();
        let back: RecipientEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.recipient.recipient_id, "1");
    }

    #[test]
    fn recipient_entry_debug() {
        let entry = RecipientEntry {
            recipient: make_recipient("1", RecipientRole::Signer, 1),
            tabs: RecipientTabs::new("1"),
        };
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("RecipientEntry"));
    }

    #[test]
    fn recipient_entry_clone() {
        let entry = RecipientEntry {
            recipient: make_recipient("1", RecipientRole::Signer, 1),
            tabs: RecipientTabs::new("1"),
        };
        let cloned = entry.clone();
        drop(entry);
        assert_eq!(cloned.recipient.recipient_id, "1");
    }

    // ===================================================================
    // Integration / workflow tests
    // ===================================================================

    #[test]
    fn workflow_build_complete_envelope() {
        let mut er = EnvelopeRecipients::new();

        // Add signer
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        // Add CC
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 2));

        // Add signature tab to signer
        let sig = TabBuilder::new(TabType::SignHere)
            .at_coordinate(1, 350, 500)
            .required()
            .build()
            .unwrap();
        er.add_tab_to_recipient("1", sig);

        // Add date signed tab
        let date = TabBuilder::new(TabType::DateSigned)
            .at_anchor("Date:", 50, 0)
            .build()
            .unwrap();
        er.add_tab_to_recipient("1", date);

        // Add text field
        let text = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 100, 600)
            .with_label("company_name")
            .with_value("Acme Corp")
            .locked()
            .with_size(200, 20)
            .build()
            .unwrap();
        er.add_tab_to_recipient("1", text);

        assert_eq!(er.recipient_count(), 2);
        assert_eq!(er.signer_count(), 1);
        assert_eq!(er.total_tab_count(), 3);
        assert!(er.has_valid_routing());

        let v = RecipientsValidator::new();
        assert!(v.validate_all(&er).is_empty());
    }

    #[test]
    fn workflow_parallel_signers() {
        let mut er = EnvelopeRecipients::new();
        er.add_recipient(make_recipient("1", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("2", RecipientRole::Signer, 1));
        er.add_recipient(make_recipient("3", RecipientRole::CarbonCopy, 2));

        er.add_tab_to_recipient("1", make_sign_tab(1, 100, 200));
        er.add_tab_to_recipient("2", make_sign_tab(1, 100, 400));

        assert_eq!(er.signer_count(), 2);
        assert!(er.has_valid_routing());
    }

    #[test]
    fn workflow_validation_catches_all_issues() {
        let v = RecipientsValidator {
            max_recipients: 1,
            max_tabs_per_recipient: 1,
            max_anchor_length: 5,
            max_value_length: 3,
        };
        let mut er = EnvelopeRecipients::new();
        // Bad recipient
        let mut bad = make_recipient("1", RecipientRole::Signer, 1);
        bad.email = String::new();
        er.add_recipient(bad);
        er.add_recipient(make_recipient("2", RecipientRole::CarbonCopy, 2));

        // Bad tab: anchor too long
        let bad_tab = TabBuilder::new(TabType::Text)
            .at_anchor("this is longer than 5", 0, 0)
            .with_value("toolong")
            .build()
            .unwrap();
        er.add_tab_to_recipient("1", bad_tab);
        er.add_tab_to_recipient("1", make_sign_tab(1, 10, 20));

        let errors = v.validate_all(&er);
        // Should have: TooManyRecipients, Recipient error, TooManyTabs, Tab errors
        assert!(errors.len() >= 4);
    }

    #[test]
    fn tab_builder_debug() {
        let builder = TabBuilder::new(TabType::SignHere);
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("TabBuilder"));
    }

    #[test]
    fn tab_builder_clone() {
        let builder = TabBuilder::new(TabType::Text).at_coordinate(1, 10, 20);
        let cloned = builder.clone();
        // Use original after clone to prove independence
        let tab_orig = builder.build().unwrap();
        assert_eq!(tab_orig.tab_type, TabType::Text);
        let tab_cloned = cloned.build().unwrap();
        assert_eq!(tab_cloned.tab_type, TabType::Text);
    }

    #[test]
    fn tab_no_value_skips_serialization() {
        let tab = make_sign_tab(1, 100, 200);
        let json = serde_json::to_value(&tab).unwrap();
        assert!(json.get("value").is_none());
    }

    #[test]
    fn tab_no_label_skips_serialization() {
        let tab = make_sign_tab(1, 100, 200);
        let json = serde_json::to_value(&tab).unwrap();
        assert!(json.get("tabLabel").is_none());
    }

    #[test]
    fn tab_no_size_skips_serialization() {
        let tab = make_sign_tab(1, 100, 200);
        let json = serde_json::to_value(&tab).unwrap();
        assert!(json.get("width").is_none());
        assert!(json.get("height").is_none());
    }

    #[test]
    fn tab_no_font_size_skips_serialization() {
        let tab = make_sign_tab(1, 100, 200);
        let json = serde_json::to_value(&tab).unwrap();
        assert!(json.get("fontSize").is_none());
    }

    #[test]
    fn recipient_no_access_code_skips_serialization() {
        let r = make_recipient("1", RecipientRole::Signer, 1);
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("accessCode").is_none());
    }

    #[test]
    fn recipient_no_id_check_skips_serialization() {
        let r = make_recipient("1", RecipientRole::Signer, 1);
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("idCheck").is_none());
    }

    #[test]
    fn anchor_no_page_skips_serialization() {
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor("Sign:", 0, 0)
            .build()
            .unwrap();
        let json = serde_json::to_value(&tab).unwrap();
        let placement = &json["placement"];
        assert!(placement.get("page").is_none());
    }

    #[test]
    fn validator_custom_limits() {
        let v = RecipientsValidator {
            max_recipients: 5,
            max_tabs_per_recipient: 10,
            max_anchor_length: 50,
            max_value_length: 100,
        };
        assert_eq!(v.max_recipients, 5);
        assert_eq!(v.max_tabs_per_recipient, 10);
        assert_eq!(v.max_anchor_length, 50);
        assert_eq!(v.max_value_length, 100);
    }

    #[test]
    fn validator_tab_value_within_limit() {
        let v = RecipientsValidator {
            max_value_length: 10,
            ..RecipientsValidator::default()
        };
        let tab = TabBuilder::new(TabType::Text)
            .at_coordinate(1, 0, 0)
            .with_value("short")
            .build()
            .unwrap();
        assert!(v.validate_tab(&tab).is_empty());
    }

    #[test]
    fn validator_tab_no_value_ok() {
        let v = RecipientsValidator::new();
        let tab = make_sign_tab(1, 100, 200);
        assert!(v.validate_tab(&tab).is_empty());
    }

    #[test]
    fn validator_anchor_at_limit() {
        let v = RecipientsValidator {
            max_anchor_length: 5,
            ..RecipientsValidator::default()
        };
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor("12345", 0, 0)
            .build()
            .unwrap();
        assert!(v.validate_tab(&tab).is_empty());
    }

    #[test]
    fn validator_anchor_one_over_limit() {
        let v = RecipientsValidator {
            max_anchor_length: 5,
            ..RecipientsValidator::default()
        };
        let tab = TabBuilder::new(TabType::Text)
            .at_anchor("123456", 0, 0)
            .build()
            .unwrap();
        let errors = v.validate_tab(&tab);
        assert!(errors.contains(&TabValidationError::AnchorTooLong));
    }
}
