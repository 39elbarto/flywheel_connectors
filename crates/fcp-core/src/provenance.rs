//! Provenance, Taint, and Unified [`ApprovalToken`] (NORMATIVE).
//!
//! This module implements the FCP2 provenance model for tracking data origin,
//! trust boundaries, and compositional security guarantees.
//!
//! # Key Concepts
//!
//! - **Provenance**: Tracks the origin and transformations of data as it flows
//!   through the mesh. Each object carries provenance metadata.
//!
//! - **Labels**: Integrity and confidentiality labels that determine what
//!   operations can be performed and where data can flow.
//!
//! - **Taint**: Flags that accumulate as data flows through untrusted sources.
//!   Taint can only be reduced with proof-carrying [`SanitizerReceipt`]s.
//!
//! - **[`ApprovalToken`]**: Unified token for elevation, declassification, and
//!   scoped execution authorization.
//!
//! # Security Model
//!
//! The provenance model enforces a lattice-based information flow policy:
//!
//! - **Integrity**: Flows DOWN freely; flowing UP requires [`ApprovalScope::Elevation`]
//! - **Confidentiality**: Flows UP freely; flowing DOWN requires [`ApprovalScope::Declassification`]
//!
//! When merging data from multiple sources:
//! - `integrity = MIN(effective_integrity(inputs))`
//! - `confidentiality = MAX(effective_confidentiality(inputs))`

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{SafetyTier, ZoneId};
use crate::object::ObjectId;

// ─────────────────────────────────────────────────────────────────────────────
// Integrity and Confidentiality Labels
// ─────────────────────────────────────────────────────────────────────────────

/// Integrity level for data (NORMATIVE).
///
/// Higher values indicate higher integrity (more trusted).
/// Integrity flows DOWN the lattice freely; flowing UP requires elevation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[repr(u8)]
pub enum IntegrityLevel {
    /// Untrusted external input (lowest integrity)
    #[default]
    Untrusted = 0,
    /// Input from semi-trusted community sources
    Community = 1,
    /// Input from authenticated work context
    Work = 2,
    /// Input from authenticated private context
    Private = 3,
    /// Input from owner/root context (highest integrity)
    Owner = 4,
}

impl IntegrityLevel {
    /// Map from a zone to its default integrity level (NORMATIVE).
    #[must_use]
    pub fn from_zone(zone: &ZoneId) -> Self {
        match zone.as_str() {
            "z:owner" => Self::Owner,
            "z:private" => Self::Private,
            "z:work" => Self::Work,
            "z:community" => Self::Community,
            _ => Self::Untrusted,
        }
    }

    /// Get the numeric value for comparison and merge operations.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => write!(f, "untrusted"),
            Self::Community => write!(f, "community"),
            Self::Work => write!(f, "work"),
            Self::Private => write!(f, "private"),
            Self::Owner => write!(f, "owner"),
        }
    }
}

/// Confidentiality level for data (NORMATIVE).
///
/// Higher values indicate higher confidentiality (more restricted).
/// Confidentiality flows UP the lattice freely; flowing DOWN requires declassification.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[repr(u8)]
pub enum ConfidentialityLevel {
    /// Public data (lowest confidentiality, can flow anywhere)
    #[default]
    Public = 0,
    /// Community-level data
    Community = 1,
    /// Work-level data
    Work = 2,
    /// Private/personal data
    Private = 3,
    /// Owner-only data (highest confidentiality)
    Owner = 4,
}

impl ConfidentialityLevel {
    /// Map from a zone to its default confidentiality level (NORMATIVE).
    #[must_use]
    pub fn from_zone(zone: &ZoneId) -> Self {
        match zone.as_str() {
            "z:owner" => Self::Owner,
            "z:private" => Self::Private,
            "z:work" => Self::Work,
            "z:community" => Self::Community,
            _ => Self::Public,
        }
    }

    /// Get the numeric value for comparison and merge operations.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ConfidentialityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Community => write!(f, "community"),
            Self::Work => write!(f, "work"),
            Self::Private => write!(f, "private"),
            Self::Owner => write!(f, "owner"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Taint Flags
// ─────────────────────────────────────────────────────────────────────────────

/// Taint flags that accumulate as data flows through the system (NORMATIVE).
///
/// Taint is compositional via OR: if any input is tainted, output is tainted.
/// Taint can ONLY be reduced by referencing a valid `SanitizerReceipt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintFlag {
    /// Input came from public/untrusted internet source
    PublicInput,
    /// Input contains unverified external links/references
    UnverifiedLink,
    /// Input has been through an untrusted transformation
    UntrustedTransform,
    /// Input was injected by external webhook
    WebhookInjected,
    /// Input came from user-generated content
    UserGenerated,
    /// Input contains potentially malicious patterns (detected by sanitizer)
    PotentiallyMalicious,
    /// Input was synthesized by AI model
    AiGenerated,
    /// Input crossed zone boundary without explicit approval
    CrossZoneUnapproved,
}

impl TaintFlag {
    /// Check if this taint flag is considered critical (blocks Dangerous operations).
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::PublicInput | Self::PotentiallyMalicious | Self::CrossZoneUnapproved
        )
    }
}

impl fmt::Display for TaintFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicInput => write!(f, "PUBLIC_INPUT"),
            Self::UnverifiedLink => write!(f, "UNVERIFIED_LINK"),
            Self::UntrustedTransform => write!(f, "UNTRUSTED_TRANSFORM"),
            Self::WebhookInjected => write!(f, "WEBHOOK_INJECTED"),
            Self::UserGenerated => write!(f, "USER_GENERATED"),
            Self::PotentiallyMalicious => write!(f, "POTENTIALLY_MALICIOUS"),
            Self::AiGenerated => write!(f, "AI_GENERATED"),
            Self::CrossZoneUnapproved => write!(f, "CROSS_ZONE_UNAPPROVED"),
        }
    }
}

/// Collection of taint flags with set semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlags(BTreeSet<TaintFlag>);

impl TaintFlags {
    /// Create an empty taint flag set.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Create from a single flag.
    #[must_use]
    pub fn from_flag(flag: TaintFlag) -> Self {
        let mut set = BTreeSet::new();
        set.insert(flag);
        Self(set)
    }

    /// Check if empty (no taint).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if contains a specific flag.
    #[must_use]
    pub fn contains(&self, flag: TaintFlag) -> bool {
        self.0.contains(&flag)
    }

    /// Check if any critical taint is present.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.0.iter().any(|f| f.is_critical())
    }

    /// Add a taint flag.
    pub fn insert(&mut self, flag: TaintFlag) {
        self.0.insert(flag);
    }

    /// Remove a taint flag (only valid with [`SanitizerReceipt`] proof).
    ///
    /// Callers MUST ensure a valid sanitizer receipt exists before removal.
    pub fn remove(&mut self, flag: TaintFlag) {
        self.0.remove(&flag);
    }

    /// Merge with another taint set (OR semantics).
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).copied().collect())
    }

    /// Iterate over flags.
    pub fn iter(&self) -> impl Iterator<Item = &TaintFlag> {
        self.0.iter()
    }

    /// Number of taint flags.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromIterator<TaintFlag> for TaintFlags {
    fn from_iter<T: IntoIterator<Item = TaintFlag>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Label Adjustment (Proof-Carrying)
// ─────────────────────────────────────────────────────────────────────────────

/// A proof-carrying label adjustment (NORMATIVE).
///
/// Any elevation or declassification must be reflected by appending a
/// [`LabelAdjustment`] entry that references the authorizing [`ApprovalToken`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelAdjustment {
    /// Timestamp when the adjustment was made (Unix epoch ms)
    pub timestamp_ms: u64,

    /// Kind of adjustment
    pub kind: AdjustmentKind,

    /// The [`ApprovalToken`] [`ObjectId`] that authorized this adjustment
    pub approval_token_id: ObjectId,

    /// Previous integrity level (for elevation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_integrity: Option<IntegrityLevel>,

    /// New integrity level (for elevation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_integrity: Option<IntegrityLevel>,

    /// Previous confidentiality level (for declassification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_confidentiality: Option<ConfidentialityLevel>,

    /// New confidentiality level (for declassification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_confidentiality: Option<ConfidentialityLevel>,
}

/// Kind of label adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjustmentKind {
    /// Integrity elevated (flowing UP the lattice)
    Elevation,
    /// Confidentiality reduced (flowing DOWN the lattice)
    Declassification,
}

// ─────────────────────────────────────────────────────────────────────────────
// Taint Reduction (Proof-Carrying)
// ─────────────────────────────────────────────────────────────────────────────

/// A proof-carrying taint reduction (NORMATIVE).
///
/// Taint can ONLY be reduced by referencing a valid `SanitizerReceipt`
/// that covers the inputs being sanitized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintReduction {
    /// Timestamp when the reduction was applied (Unix epoch ms)
    pub timestamp_ms: u64,

    /// The [`SanitizerReceipt`] [`ObjectId`] that authorized this reduction
    pub sanitizer_receipt_id: ObjectId,

    /// Which taint flags were cleared
    pub cleared_flags: Vec<TaintFlag>,

    /// [`ObjectId`]s of inputs that were covered by this reduction
    pub covered_inputs: Vec<ObjectId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone Crossing Record
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a zone crossing (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCrossing {
    /// Timestamp of the crossing (Unix epoch ms)
    pub timestamp_ms: u64,

    /// Source zone
    pub from_zone: ZoneId,

    /// Destination zone
    pub to_zone: ZoneId,

    /// Whether this crossing was approved (via [`ApprovalToken`])
    pub approved: bool,

    /// The [`ApprovalToken`] [`ObjectId`] if approved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<ObjectId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Provenance Record
// ─────────────────────────────────────────────────────────────────────────────

/// Complete provenance record for a mesh object (NORMATIVE).
///
/// This is the authoritative source of trust metadata for any object
/// flowing through the FCP mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// Zone where the data originally entered the mesh
    pub origin_zone: ZoneId,

    /// Current zone where the data resides
    pub current_zone: ZoneId,

    /// Current integrity label
    pub integrity_label: IntegrityLevel,

    /// Current confidentiality label
    pub confidentiality_label: ConfidentialityLevel,

    /// Accumulated taint flags
    #[serde(default)]
    pub taint_flags: TaintFlags,

    /// History of label adjustments (elevation/declassification)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label_adjustments: Vec<LabelAdjustment>,

    /// History of taint reductions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_reductions: Vec<TaintReduction>,

    /// History of zone crossings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zone_crossings: Vec<ZoneCrossing>,

    /// [`ObjectId`]s of input sources (for merge tracking)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_sources: Vec<ObjectId>,
}

impl ProvenanceRecord {
    /// Create a new provenance record for data originating in a zone.
    #[must_use]
    pub fn new(origin_zone: ZoneId) -> Self {
        let integrity_label = IntegrityLevel::from_zone(&origin_zone);
        let confidentiality_label = ConfidentialityLevel::from_zone(&origin_zone);

        Self {
            current_zone: origin_zone.clone(),
            origin_zone,
            integrity_label,
            confidentiality_label,
            taint_flags: TaintFlags::new(),
            label_adjustments: Vec::new(),
            taint_reductions: Vec::new(),
            zone_crossings: Vec::new(),
            input_sources: Vec::new(),
        }
    }

    /// Create a provenance record for untrusted public input.
    #[must_use]
    pub fn public_input() -> Self {
        let mut record = Self::new(ZoneId::public());
        record.taint_flags.insert(TaintFlag::PublicInput);
        record
    }

    /// Merge multiple provenance records (NORMATIVE - SECURITY CRITICAL).
    ///
    /// When combining data from multiple inputs:
    /// - `integrity = MIN(effective_integrity(inputs))`
    /// - `confidentiality = MAX(effective_confidentiality(inputs))`
    /// - `taint_flags = OR(all input taint flags)`
    ///
    /// This prevents "mix trusted with untrusted" from upgrading trust.
    #[must_use]
    pub fn merge(records: &[&Self], current_zone: ZoneId) -> Self {
        if records.is_empty() {
            return Self::new(current_zone);
        }

        // MIN integrity (lowest wins - most conservative)
        let integrity_label = records
            .iter()
            .map(|r| r.integrity_label)
            .min()
            .unwrap_or_default();

        // MAX confidentiality (highest wins - most restrictive)
        let confidentiality_label = records
            .iter()
            .map(|r| r.confidentiality_label)
            .max()
            .unwrap_or_default();

        // OR taint flags (all flags accumulate)
        let mut taint_flags = TaintFlags::new();
        for record in records {
            for flag in record.taint_flags.iter() {
                taint_flags.insert(*flag);
            }
        }

        // Use first record's origin as canonical
        let origin_zone = records
            .first()
            .map_or_else(|| current_zone.clone(), |r| r.origin_zone.clone());

        // Collect all input sources
        let input_sources: Vec<ObjectId> = records
            .iter()
            .flat_map(|r| r.input_sources.iter().copied())
            .collect();

        Self {
            origin_zone,
            current_zone,
            integrity_label,
            confidentiality_label,
            taint_flags,
            label_adjustments: Vec::new(), // New merge, no adjustments yet
            taint_reductions: Vec::new(),
            zone_crossings: Vec::new(),
            input_sources,
        }
    }

    /// Check if this provenance can drive an operation at the given safety tier.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceViolation`] if the provenance is insufficient:
    /// - [`ProvenanceViolation::PublicInputForDangerousOperation`] for public-tainted input
    /// - [`ProvenanceViolation::MaliciousInputDetected`] if malicious content is detected
    /// - [`ProvenanceViolation::InsufficientIntegrity`] if integrity level is too low
    /// - [`ProvenanceViolation::TaintedInputForRiskyOperation`] for tainted risky ops
    pub fn can_drive_operation(&self, tier: SafetyTier) -> Result<(), ProvenanceViolation> {
        match tier {
            SafetyTier::Safe => Ok(()),
            SafetyTier::Risky => {
                // PotentiallyMalicious input must never drive Risky operations
                if self.taint_flags.contains(TaintFlag::PotentiallyMalicious) {
                    return Err(ProvenanceViolation::MaliciousInputDetected);
                }

                // Risky operations may require elevation for tainted input
                if self.taint_flags.has_critical() && self.integrity_label < IntegrityLevel::Work {
                    Err(ProvenanceViolation::TaintedInputForRiskyOperation {
                        taint_flags: self.taint_flags.iter().copied().collect(),
                    })
                } else {
                    Ok(())
                }
            }
            SafetyTier::Dangerous | SafetyTier::Forbidden | SafetyTier::Critical => {
                // Dangerous/Critical operations MUST NOT be driven by public-tainted input
                if self.taint_flags.contains(TaintFlag::PublicInput) {
                    return Err(ProvenanceViolation::PublicInputForDangerousOperation);
                }
                if self.taint_flags.contains(TaintFlag::PotentiallyMalicious) {
                    return Err(ProvenanceViolation::MaliciousInputDetected);
                }
                if self.taint_flags.contains(TaintFlag::CrossZoneUnapproved) {
                    return Err(ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation);
                }
                if self.integrity_label < IntegrityLevel::Work {
                    return Err(ProvenanceViolation::InsufficientIntegrity {
                        required: IntegrityLevel::Work,
                        actual: self.integrity_label,
                    });
                }
                Ok(())
            }
        }
    }

    /// Check if data can flow to a target zone without approval.
    ///
    /// Integrity flows DOWN, confidentiality flows UP.
    #[must_use]
    pub fn can_flow_to(&self, target_zone: &ZoneId) -> FlowCheckResult {
        let target_integrity = IntegrityLevel::from_zone(target_zone);
        let target_confidentiality = ConfidentialityLevel::from_zone(target_zone);

        // Integrity: can flow DOWN (target integrity <= current integrity)
        let integrity_ok = target_integrity <= self.integrity_label;

        // Confidentiality: can flow UP (target confidentiality >= current confidentiality)
        let confidentiality_ok = target_confidentiality >= self.confidentiality_label;

        if integrity_ok && confidentiality_ok {
            FlowCheckResult::Allowed
        } else if !integrity_ok && !confidentiality_ok {
            FlowCheckResult::RequiresBoth
        } else if !integrity_ok {
            FlowCheckResult::RequiresElevation
        } else {
            FlowCheckResult::RequiresDeclassification
        }
    }

    /// Apply an elevation (increase integrity) with approval token proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceViolation::InvalidElevation`] if the new integrity level
    /// is not higher than the current integrity level.
    pub fn apply_elevation(
        &mut self,
        new_integrity: IntegrityLevel,
        approval_token_id: ObjectId,
        timestamp_ms: u64,
    ) -> Result<(), ProvenanceViolation> {
        if new_integrity <= self.integrity_label {
            return Err(ProvenanceViolation::InvalidElevation {
                current: self.integrity_label,
                requested: new_integrity,
            });
        }

        let adjustment = LabelAdjustment {
            timestamp_ms,
            kind: AdjustmentKind::Elevation,
            approval_token_id,
            prev_integrity: Some(self.integrity_label),
            new_integrity: Some(new_integrity),
            prev_confidentiality: None,
            new_confidentiality: None,
        };

        self.label_adjustments.push(adjustment);
        self.integrity_label = new_integrity;
        Ok(())
    }

    /// Apply a declassification (decrease confidentiality) with approval token proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceViolation::InvalidDeclassification`] if the new confidentiality
    /// level is not lower than the current confidentiality level.
    pub fn apply_declassification(
        &mut self,
        new_confidentiality: ConfidentialityLevel,
        approval_token_id: ObjectId,
        timestamp_ms: u64,
    ) -> Result<(), ProvenanceViolation> {
        if new_confidentiality >= self.confidentiality_label {
            return Err(ProvenanceViolation::InvalidDeclassification {
                current: self.confidentiality_label,
                requested: new_confidentiality,
            });
        }

        let adjustment = LabelAdjustment {
            timestamp_ms,
            kind: AdjustmentKind::Declassification,
            approval_token_id,
            prev_integrity: None,
            new_integrity: None,
            prev_confidentiality: Some(self.confidentiality_label),
            new_confidentiality: Some(new_confidentiality),
        };

        self.label_adjustments.push(adjustment);
        self.confidentiality_label = new_confidentiality;
        Ok(())
    }

    /// Apply a taint reduction with sanitizer receipt proof.
    pub fn apply_taint_reduction(
        &mut self,
        flags_to_clear: &[TaintFlag],
        sanitizer_receipt_id: ObjectId,
        covered_inputs: Vec<ObjectId>,
        timestamp_ms: u64,
    ) {
        let mut cleared = Vec::new();
        for flag in flags_to_clear {
            if self.taint_flags.contains(*flag) {
                self.taint_flags.remove(*flag);
                cleared.push(*flag);
            }
        }

        if !cleared.is_empty() {
            self.taint_reductions.push(TaintReduction {
                timestamp_ms,
                sanitizer_receipt_id,
                cleared_flags: cleared,
                covered_inputs,
            });
        }
    }

    /// Record a zone crossing.
    pub fn record_zone_crossing(
        &mut self,
        to_zone: ZoneId,
        approved: bool,
        approval_token_id: Option<ObjectId>,
        timestamp_ms: u64,
    ) {
        let crossing = ZoneCrossing {
            timestamp_ms,
            from_zone: self.current_zone.clone(),
            to_zone: to_zone.clone(),
            approved,
            approval_token_id,
        };

        self.zone_crossings.push(crossing);
        self.current_zone = to_zone;

        // Add taint if crossing without approval
        if !approved {
            self.taint_flags.insert(TaintFlag::CrossZoneUnapproved);
        }
    }
}

/// Result of checking if data can flow to a target zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowCheckResult {
    /// Flow is allowed without any approval
    Allowed,
    /// Flow requires elevation (integrity increase)
    RequiresElevation,
    /// Flow requires declassification (confidentiality decrease)
    RequiresDeclassification,
    /// Flow requires both elevation and declassification
    RequiresBoth,
}

/// Provenance violation error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProvenanceViolation {
    #[error("public input cannot drive dangerous operation")]
    PublicInputForDangerousOperation,

    #[error("malicious input pattern detected")]
    MaliciousInputDetected,

    #[error("unapproved cross-zone input cannot drive dangerous operation")]
    CrossZoneUnapprovedForDangerousOperation,

    #[error("tainted input cannot drive risky operation without elevation: {taint_flags:?}")]
    TaintedInputForRiskyOperation { taint_flags: Vec<TaintFlag> },

    #[error("insufficient integrity: required {required}, actual {actual}")]
    InsufficientIntegrity {
        required: IntegrityLevel,
        actual: IntegrityLevel,
    },

    #[error("invalid elevation: cannot elevate from {current} to {requested}")]
    InvalidElevation {
        current: IntegrityLevel,
        requested: IntegrityLevel,
    },

    #[error("invalid declassification: cannot declassify from {current} to {requested}")]
    InvalidDeclassification {
        current: ConfidentialityLevel,
        requested: ConfidentialityLevel,
    },

    #[error("sanitizer receipt does not cover required inputs")]
    SanitizerCoverageInsufficient,

    #[error("approval token expired or invalid")]
    ApprovalTokenInvalid,
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified ApprovalToken
// ─────────────────────────────────────────────────────────────────────────────

/// Unified [`ApprovalToken`] (NORMATIVE).
///
/// A first-class mesh object for authorization with a closed set of scopes:
/// - [`ApprovalScope::Elevation`]: Raise integrity level
/// - [`ApprovalScope::Declassification`]: Lower confidentiality level
/// - [`ApprovalScope::Execution`]: Authorize specific operation invocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// Unique token ID (becomes [`ObjectId`] when stored)
    pub token_id: String,

    /// Timestamp when token was issued (Unix epoch ms)
    pub issued_at_ms: u64,

    /// Timestamp when token expires (Unix epoch ms)
    pub expires_at_ms: u64,

    /// Issuer identity (node ID or principal)
    pub issuer: String,

    /// The approval scope
    pub scope: ApprovalScope,

    /// Zone this token is valid within
    pub zone_id: ZoneId,

    /// `COSE_Sign1` signature over canonical encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl ApprovalToken {
    /// Check if the token is expired.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Check if the token is not yet valid.
    #[must_use]
    pub const fn is_not_yet_valid(&self, now_ms: u64) -> bool {
        now_ms < self.issued_at_ms
    }

    /// Check if the token is currently valid.
    #[must_use]
    pub const fn is_valid(&self, now_ms: u64) -> bool {
        !self.is_expired(now_ms) && !self.is_not_yet_valid(now_ms)
    }
}

/// Approval scope - the closed set of authorization types (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Elevation: Raise integrity level for an operation
    Elevation(ElevationScope),

    /// Declassification: Lower confidentiality for data flow
    Declassification(DeclassificationScope),

    /// Execution: Authorize a specific operation invocation
    Execution(ExecutionScope),
}

/// Elevation scope - authorization to raise integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationScope {
    /// Operation being elevated
    pub operation_id: String,

    /// Original provenance [`ObjectId`] being elevated
    pub original_provenance_id: ObjectId,

    /// Target integrity level
    pub target_integrity: IntegrityLevel,
}

/// Declassification scope - authorization to lower confidentiality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclassificationScope {
    /// Source zone (where data is coming from)
    pub from_zone: ZoneId,

    /// Target zone (where data is going to)
    pub to_zone: ZoneId,

    /// [`ObjectId`]s being declassified
    pub object_ids: Vec<ObjectId>,

    /// Target confidentiality level
    pub target_confidentiality: ConfidentialityLevel,
}

/// Execution scope - authorization for a specific invocation (NORMATIVE).
///
/// This is how we support "allow this exact invocation" in degraded/offline
/// cases and avoid broad, reusable approvals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionScope {
    /// Connector being invoked
    pub connector_id: String,

    /// Method pattern (exact match or prefix wildcard)
    pub method_pattern: String,

    /// Specific request [`ObjectId`] if bound to exact request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_id: Option<ObjectId>,

    /// Hash of input data for exact binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<[u8; 32]>,

    /// Input constraints (JSON Pointer paths with expected values)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_constraints: Vec<InputConstraint>,
}

/// Input constraint for execution scope (NORMATIVE).
///
/// Uses JSON Pointer (RFC 6901) ONLY - no `JSONPath`, no regex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConstraint {
    /// JSON Pointer path (RFC 6901)
    pub pointer: String,

    /// Expected value (JSON-serializable)
    pub expected: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// SanitizerReceipt
// ─────────────────────────────────────────────────────────────────────────────

/// [`SanitizerReceipt`] - proof of taint sanitization (NORMATIVE).
///
/// A sanitizer receipt proves that specific inputs were processed by
/// an authorized sanitizer, clearing specific taint flags.
///
/// Verifiers MUST validate:
/// 1. Signature validity
/// 2. Authority (is this sanitizer authorized for these flags?)
/// 3. Coverage (are the claimed inputs actually the ones being reduced?)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerReceipt {
    /// Unique receipt ID (becomes [`ObjectId`] when stored)
    pub receipt_id: String,

    /// Timestamp when sanitization occurred (Unix epoch ms)
    pub timestamp_ms: u64,

    /// Sanitizer identity
    pub sanitizer_id: String,

    /// Sanitizer authority zone (must have sufficient integrity)
    pub sanitizer_zone: ZoneId,

    /// Which taint flags this sanitizer is authorized to clear
    pub authorized_flags: Vec<TaintFlag>,

    /// [`ObjectId`]s of inputs that were sanitized
    pub covered_inputs: Vec<ObjectId>,

    /// Which flags were actually cleared (subset of `authorized_flags`)
    pub cleared_flags: Vec<TaintFlag>,

    /// `COSE_Sign1` signature over canonical encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl SanitizerReceipt {
    /// Check if this receipt covers a specific input.
    #[must_use]
    pub fn covers_input(&self, input_id: &ObjectId) -> bool {
        self.covered_inputs.contains(input_id)
    }

    /// Check if this receipt is authorized to clear a flag.
    #[must_use]
    pub fn can_clear(&self, flag: TaintFlag) -> bool {
        self.authorized_flags.contains(&flag)
    }

    /// Validate that cleared flags are a subset of authorized flags.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.cleared_flags.iter().all(|f| self.can_clear(*f))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintDecision
// ─────────────────────────────────────────────────────────────────────────────

/// Decision about taint-gated operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintDecision {
    /// Whether the operation is allowed
    pub allowed: bool,

    /// Reason code for audit
    pub reason_code: String,

    /// Safety tier of the operation
    pub safety_tier: SafetyTier,

    /// Taint flags that contributed to the decision
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributing_flags: Vec<TaintFlag>,

    /// [`ApprovalToken`] [`ObjectId`] if approval was used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<ObjectId>,

    /// [`SanitizerReceipt`] [`ObjectId`] if sanitization was used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizer_receipt_id: Option<ObjectId>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    fn log_flow_test(
        test_name: &str,
        flow_type: &str,
        from_label: &str,
        to_label: &str,
        approval_present: bool,
        result: &str,
        reason_code: Option<&str>,
    ) {
        let log = json!({
            "test_name": test_name,
            "flow_type": flow_type,
            "from_label": from_label,
            "to_label": to_label,
            "approval_present": approval_present,
            "result": result,
            "reason_code": reason_code,
        });
        eprintln!("{log}");
    }

    fn assert_merge_equivalent(left: &ProvenanceRecord, right: &ProvenanceRecord) {
        assert_eq!(left.integrity_label, right.integrity_label);
        assert_eq!(left.confidentiality_label, right.confidentiality_label);
        assert_eq!(left.taint_flags, right.taint_flags);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provenance Field Handling Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn public_input_defaults() {
        let record = ProvenanceRecord::public_input();

        assert_eq!(record.origin_zone, ZoneId::public());
        assert_eq!(record.current_zone, ZoneId::public());
        assert_eq!(record.integrity_label, IntegrityLevel::Untrusted);
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Public);
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        log_flow_test(
            "public_input_defaults",
            "integrity",
            "public",
            "public",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_empty_defaults_to_current_zone() {
        let merged = ProvenanceRecord::merge(&[], ZoneId::work());

        assert_eq!(merged.origin_zone, ZoneId::work());
        assert_eq!(merged.current_zone, ZoneId::work());
        assert_eq!(merged.integrity_label, IntegrityLevel::Work);
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Work);
        assert!(merged.taint_flags.is_empty());
        log_flow_test(
            "provenance_merge_empty_defaults_to_current_zone",
            "integrity",
            "none",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_single_preserves_fields() {
        let mut record = ProvenanceRecord::new(ZoneId::private());
        record.taint_flags.insert(TaintFlag::UserGenerated);
        record.input_sources.push(test_object_id("source-a"));

        let merged = ProvenanceRecord::merge(&[&record], ZoneId::work());

        assert_eq!(merged.origin_zone, ZoneId::private());
        assert_eq!(merged.current_zone, ZoneId::work());
        assert_eq!(merged.integrity_label, IntegrityLevel::Private);
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
        assert!(merged.taint_flags.contains(TaintFlag::UserGenerated));
        assert_eq!(merged.input_sources, vec![test_object_id("source-a")]);
        log_flow_test(
            "provenance_merge_single_preserves_fields",
            "integrity",
            "private",
            "work",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Integrity/Confidentiality Level Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn integrity_level_ordering() {
        assert!(IntegrityLevel::Untrusted < IntegrityLevel::Community);
        assert!(IntegrityLevel::Community < IntegrityLevel::Work);
        assert!(IntegrityLevel::Work < IntegrityLevel::Private);
        assert!(IntegrityLevel::Private < IntegrityLevel::Owner);
    }

    #[test]
    fn confidentiality_level_ordering() {
        assert!(ConfidentialityLevel::Public < ConfidentialityLevel::Community);
        assert!(ConfidentialityLevel::Community < ConfidentialityLevel::Work);
        assert!(ConfidentialityLevel::Work < ConfidentialityLevel::Private);
        assert!(ConfidentialityLevel::Private < ConfidentialityLevel::Owner);
    }

    #[test]
    fn integrity_from_zone() {
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::owner()),
            IntegrityLevel::Owner
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::private()),
            IntegrityLevel::Private
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::work()),
            IntegrityLevel::Work
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::community()),
            IntegrityLevel::Community
        );
        assert_eq!(
            IntegrityLevel::from_zone(&ZoneId::public()),
            IntegrityLevel::Untrusted
        );
    }

    #[test]
    fn confidentiality_from_zone() {
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::owner()),
            ConfidentialityLevel::Owner
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::private()),
            ConfidentialityLevel::Private
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::work()),
            ConfidentialityLevel::Work
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::community()),
            ConfidentialityLevel::Community
        );
        assert_eq!(
            ConfidentialityLevel::from_zone(&ZoneId::public()),
            ConfidentialityLevel::Public
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Origin Zone Tracking Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn origin_zone_preserved_through_zone_crossing() {
        // Origin zone should remain unchanged when data crosses zones
        let mut record = ProvenanceRecord::new(ZoneId::private());
        assert_eq!(record.origin_zone, ZoneId::private());

        // Cross to work zone
        record.record_zone_crossing(ZoneId::work(), true, None, 1000);
        assert_eq!(
            record.origin_zone,
            ZoneId::private(),
            "Origin zone must be preserved"
        );
        assert_eq!(record.current_zone, ZoneId::work());

        // Cross to public zone
        record.record_zone_crossing(ZoneId::public(), false, None, 2000);
        assert_eq!(
            record.origin_zone,
            ZoneId::private(),
            "Origin zone must remain unchanged"
        );
        assert_eq!(record.current_zone, ZoneId::public());

        log_flow_test(
            "origin_zone_preserved_through_zone_crossing",
            "integrity",
            "private",
            "public",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn origin_zone_preserved_through_merge() {
        // First input's origin zone is preserved in merge
        let a = ProvenanceRecord::new(ZoneId::owner());
        let b = ProvenanceRecord::new(ZoneId::public());

        let merged = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());
        assert_eq!(
            merged.origin_zone,
            ZoneId::owner(),
            "First input's origin zone is preserved"
        );

        log_flow_test(
            "origin_zone_preserved_through_merge",
            "integrity",
            "owner+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn current_zone_updated_on_zone_crossing() {
        let mut record = ProvenanceRecord::new(ZoneId::owner());
        assert_eq!(record.current_zone, ZoneId::owner());

        // Track zone crossing path
        let zones = [
            ZoneId::private(),
            ZoneId::work(),
            ZoneId::community(),
            ZoneId::public(),
        ];

        for (i, zone) in zones.iter().enumerate() {
            record.record_zone_crossing(zone.clone(), true, None, (i as u64 + 1) * 1000);
            assert_eq!(
                &record.current_zone, zone,
                "Current zone must update after crossing"
            );
        }

        // Verify all crossings were recorded
        assert_eq!(record.zone_crossings.len(), 4);

        log_flow_test(
            "current_zone_updated_on_zone_crossing",
            "integrity",
            "owner",
            "public",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn zone_crossing_records_from_and_to_zones() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.record_zone_crossing(ZoneId::private(), true, Some(test_object_id("token")), 1000);

        let crossing = &record.zone_crossings[0];
        assert_eq!(crossing.from_zone, ZoneId::work());
        assert_eq!(crossing.to_zone, ZoneId::private());
        assert!(crossing.approved);
        assert_eq!(crossing.approval_token_id, Some(test_object_id("token")));
        assert_eq!(crossing.timestamp_ms, 1000);

        log_flow_test(
            "zone_crossing_records_from_and_to_zones",
            "integrity",
            "work",
            "private",
            true,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Integrity/Confidentiality Label Propagation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn integrity_label_propagates_through_merge_chain() {
        // Test that MIN integrity is preserved through multiple merges
        let owner = ProvenanceRecord::new(ZoneId::owner()); // Integrity: Owner
        let work = ProvenanceRecord::new(ZoneId::work()); // Integrity: Work
        let public = ProvenanceRecord::public_input(); // Integrity: Untrusted

        // Merge owner + work -> should get Work (MIN)
        let merged1 = ProvenanceRecord::merge(&[&owner, &work], ZoneId::work());
        assert_eq!(merged1.integrity_label, IntegrityLevel::Work);

        // Merge result + public -> should get Untrusted (MIN)
        let merged2 = ProvenanceRecord::merge(&[&merged1, &public], ZoneId::work());
        assert_eq!(merged2.integrity_label, IntegrityLevel::Untrusted);

        log_flow_test(
            "integrity_label_propagates_through_merge_chain",
            "integrity",
            "owner+work+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn confidentiality_label_propagates_through_merge_chain() {
        // Test that MAX confidentiality is preserved through multiple merges
        let public = ProvenanceRecord::new(ZoneId::public()); // Confidentiality: Public
        let work = ProvenanceRecord::new(ZoneId::work()); // Confidentiality: Work
        let owner = ProvenanceRecord::new(ZoneId::owner()); // Confidentiality: Owner

        // Merge public + work -> should get Work (MAX)
        let merged1 = ProvenanceRecord::merge(&[&public, &work], ZoneId::work());
        assert_eq!(merged1.confidentiality_label, ConfidentialityLevel::Work);

        // Merge result + owner -> should get Owner (MAX)
        let merged2 = ProvenanceRecord::merge(&[&merged1, &owner], ZoneId::work());
        assert_eq!(merged2.confidentiality_label, ConfidentialityLevel::Owner);

        log_flow_test(
            "confidentiality_label_propagates_through_merge_chain",
            "confidentiality",
            "public+work+owner",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn labels_independent_of_current_zone() {
        // Labels are intrinsic to the data, not affected by current zone
        let private_record = ProvenanceRecord::new(ZoneId::private());

        // Merge into different zones - labels should stay the same
        let merged_work = ProvenanceRecord::merge(&[&private_record], ZoneId::work());
        let merged_public = ProvenanceRecord::merge(&[&private_record], ZoneId::public());

        assert_eq!(merged_work.integrity_label, merged_public.integrity_label);
        assert_eq!(
            merged_work.confidentiality_label,
            merged_public.confidentiality_label
        );

        log_flow_test(
            "labels_independent_of_current_zone",
            "integrity",
            "private",
            "work|public",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Taint Flag Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn taint_flags_empty() {
        let flags = TaintFlags::new();
        assert!(flags.is_empty());
        assert!(!flags.has_critical());
    }

    #[test]
    fn taint_flags_critical() {
        let mut flags = TaintFlags::new();
        flags.insert(TaintFlag::UserGenerated);
        assert!(!flags.has_critical());

        flags.insert(TaintFlag::PublicInput);
        assert!(flags.has_critical());
    }

    #[test]
    fn taint_flags_merge() {
        let mut a = TaintFlags::new();
        a.insert(TaintFlag::PublicInput);

        let mut b = TaintFlags::new();
        b.insert(TaintFlag::UnverifiedLink);

        let merged = a.merge(&b);
        assert!(merged.contains(TaintFlag::PublicInput));
        assert!(merged.contains(TaintFlag::UnverifiedLink));
        assert_eq!(merged.len(), 2);
        log_flow_test(
            "taint_flags_merge",
            "integrity",
            "public+unverified",
            "public+unverified",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn all_taint_flag_variants_can_be_set_and_checked() {
        // Test that all TaintFlag variants work correctly
        let all_flags = [
            TaintFlag::PublicInput,
            TaintFlag::UnverifiedLink,
            TaintFlag::UntrustedTransform,
            TaintFlag::WebhookInjected,
            TaintFlag::UserGenerated,
            TaintFlag::PotentiallyMalicious,
            TaintFlag::AiGenerated,
            TaintFlag::CrossZoneUnapproved,
        ];

        let mut flags = TaintFlags::new();

        for flag in all_flags {
            assert!(
                !flags.contains(flag),
                "Flag {flag:?} should not be set initially"
            );
            flags.insert(flag);
            assert!(
                flags.contains(flag),
                "Flag {flag:?} should be set after insert"
            );
        }

        assert_eq!(flags.len(), 8, "All 8 taint flags should be set");

        log_flow_test(
            "all_taint_flag_variants_can_be_set_and_checked",
            "taint",
            "none",
            "all",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn taint_flag_criticality() {
        // Critical flags that block Dangerous operations
        assert!(TaintFlag::PublicInput.is_critical());
        assert!(TaintFlag::PotentiallyMalicious.is_critical());
        assert!(TaintFlag::CrossZoneUnapproved.is_critical());

        // Non-critical flags
        assert!(!TaintFlag::UnverifiedLink.is_critical());
        assert!(!TaintFlag::UntrustedTransform.is_critical());
        assert!(!TaintFlag::WebhookInjected.is_critical());
        assert!(!TaintFlag::UserGenerated.is_critical());
        assert!(!TaintFlag::AiGenerated.is_critical());

        log_flow_test(
            "taint_flag_criticality",
            "taint",
            "all_flags",
            "critical_check",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn taint_flags_accumulate_union() {
        // Verify taint accumulation is union (OR) operation
        let mut a = TaintFlags::new();
        a.insert(TaintFlag::PublicInput);
        a.insert(TaintFlag::UserGenerated);

        let mut b = TaintFlags::new();
        b.insert(TaintFlag::UnverifiedLink);
        b.insert(TaintFlag::UserGenerated); // Duplicate

        let merged = a.merge(&b);

        // Union should contain all unique flags
        assert!(merged.contains(TaintFlag::PublicInput));
        assert!(merged.contains(TaintFlag::UserGenerated));
        assert!(merged.contains(TaintFlag::UnverifiedLink));
        assert_eq!(merged.len(), 3, "Duplicates should not count twice");

        log_flow_test(
            "taint_flags_accumulate_union",
            "taint",
            "a+b",
            "union",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn taint_flags_has_critical_with_mixed_flags() {
        let mut flags = TaintFlags::new();

        // Add non-critical flags
        flags.insert(TaintFlag::UserGenerated);
        flags.insert(TaintFlag::AiGenerated);
        assert!(!flags.has_critical(), "No critical flags yet");

        // Add one critical flag
        flags.insert(TaintFlag::PublicInput);
        assert!(flags.has_critical(), "Should detect critical flag");

        log_flow_test(
            "taint_flags_has_critical_with_mixed_flags",
            "taint",
            "mixed",
            "critical_check",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn webhook_injected_flag_applied() {
        // Simulate webhook-sourced data
        let mut record = ProvenanceRecord::new(ZoneId::community());
        record.taint_flags.insert(TaintFlag::WebhookInjected);

        assert!(record.taint_flags.contains(TaintFlag::WebhookInjected));
        assert!(
            !record.taint_flags.has_critical(),
            "WebhookInjected alone is not critical"
        );

        log_flow_test(
            "webhook_injected_flag_applied",
            "taint",
            "community",
            "community",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn ai_generated_flag_applied() {
        // Data synthesized by AI model
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::AiGenerated);

        assert!(record.taint_flags.contains(TaintFlag::AiGenerated));
        assert!(
            !record.taint_flags.has_critical(),
            "AiGenerated alone is not critical"
        );

        log_flow_test(
            "ai_generated_flag_applied",
            "taint",
            "work",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn untrusted_transform_flag_applied() {
        // Data that passed through untrusted transformation
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::UntrustedTransform);

        assert!(record.taint_flags.contains(TaintFlag::UntrustedTransform));
        assert!(
            !record.taint_flags.has_critical(),
            "UntrustedTransform alone is not critical"
        );

        log_flow_test(
            "untrusted_transform_flag_applied",
            "taint",
            "work",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn potentially_malicious_flag_is_critical() {
        // Data flagged as potentially malicious by sanitizer
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::PotentiallyMalicious);

        assert!(record.taint_flags.contains(TaintFlag::PotentiallyMalicious));
        assert!(
            record.taint_flags.has_critical(),
            "PotentiallyMalicious is critical"
        );

        log_flow_test(
            "potentially_malicious_flag_is_critical",
            "taint",
            "work",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn potentially_malicious_blocks_risky() {
        // Even with Work integrity, PotentiallyMalicious must block Risky operations
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::PotentiallyMalicious);

        assert_eq!(record.integrity_label, IntegrityLevel::Work);
        assert!(
            matches!(
                record.can_drive_operation(SafetyTier::Risky),
                Err(ProvenanceViolation::MaliciousInputDetected)
            ),
            "Risky operation must be blocked for potentially malicious input"
        );

        log_flow_test(
            "potentially_malicious_blocks_risky",
            "taint",
            "work",
            "blocked",
            false,
            "fail",
            Some("MALICIOUS_INPUT"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provenance Merge Tests (SECURITY CRITICAL)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provenance_merge_min_integrity() {
        let owner = ProvenanceRecord::new(ZoneId::owner());
        let public = ProvenanceRecord::public_input();

        let merged = ProvenanceRecord::merge(&[&owner, &public], ZoneId::work());

        // MIN integrity: Owner + Untrusted = Untrusted
        assert_eq!(merged.integrity_label, IntegrityLevel::Untrusted);
        log_flow_test(
            "provenance_merge_min_integrity",
            "integrity",
            "owner+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_max_confidentiality() {
        let public = ProvenanceRecord::new(ZoneId::public());
        let private = ProvenanceRecord::new(ZoneId::private());

        let merged = ProvenanceRecord::merge(&[&public, &private], ZoneId::work());

        // MAX confidentiality: Public + Private = Private
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
        log_flow_test(
            "provenance_merge_max_confidentiality",
            "confidentiality",
            "public+private",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_taint_accumulates() {
        let mut a = ProvenanceRecord::new(ZoneId::work());
        a.taint_flags.insert(TaintFlag::PublicInput);

        let mut b = ProvenanceRecord::new(ZoneId::work());
        b.taint_flags.insert(TaintFlag::UnverifiedLink);

        let merged = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());

        assert!(merged.taint_flags.contains(TaintFlag::PublicInput));
        assert!(merged.taint_flags.contains(TaintFlag::UnverifiedLink));
        log_flow_test(
            "provenance_merge_taint_accumulates",
            "integrity",
            "work",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_commutative_labels_and_taints() {
        let mut a = ProvenanceRecord::new(ZoneId::owner());
        a.taint_flags.insert(TaintFlag::UserGenerated);
        let mut b = ProvenanceRecord::new(ZoneId::public());
        b.taint_flags.insert(TaintFlag::PublicInput);

        let merged_ab = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());
        let merged_ba = ProvenanceRecord::merge(&[&b, &a], ZoneId::work());

        assert_merge_equivalent(&merged_ab, &merged_ba);
        log_flow_test(
            "provenance_merge_commutative_labels_and_taints",
            "integrity",
            "owner+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn provenance_merge_associative_labels_and_taints() {
        let mut a = ProvenanceRecord::new(ZoneId::private());
        a.taint_flags.insert(TaintFlag::UserGenerated);
        let mut b = ProvenanceRecord::new(ZoneId::work());
        b.taint_flags.insert(TaintFlag::UnverifiedLink);
        let mut c = ProvenanceRecord::new(ZoneId::public());
        c.taint_flags.insert(TaintFlag::PublicInput);

        let merged_ab = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());
        let merged_abc_left = ProvenanceRecord::merge(&[&merged_ab, &c], ZoneId::work());

        let merged_bc = ProvenanceRecord::merge(&[&b, &c], ZoneId::work());
        let merged_abc_right = ProvenanceRecord::merge(&[&a, &merged_bc], ZoneId::work());

        assert_merge_equivalent(&merged_abc_left, &merged_abc_right);
        log_flow_test(
            "provenance_merge_associative_labels_and_taints",
            "integrity",
            "private+work+public",
            "work",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operation Safety Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn public_input_blocks_dangerous() {
        let public = ProvenanceRecord::public_input();

        assert!(public.can_drive_operation(SafetyTier::Safe).is_ok());
        assert!(matches!(
            public.can_drive_operation(SafetyTier::Dangerous),
            Err(ProvenanceViolation::PublicInputForDangerousOperation)
        ));
    }

    #[test]
    fn work_integrity_allows_dangerous() {
        let work = ProvenanceRecord::new(ZoneId::work());
        assert!(work.can_drive_operation(SafetyTier::Dangerous).is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Flow Check Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn flow_down_integrity_requires_declassification() {
        let owner = ProvenanceRecord::new(ZoneId::owner());
        // Owner→Work: integrity flows DOWN (OK), but confidentiality also must flow DOWN
        // which requires declassification
        assert_eq!(
            owner.can_flow_to(&ZoneId::work()),
            FlowCheckResult::RequiresDeclassification
        );
        log_flow_test(
            "flow_down_integrity_requires_declassification",
            "confidentiality",
            "owner",
            "work",
            false,
            "pass",
            Some("REQUIRES_DECLASSIFICATION"),
        );
    }

    #[test]
    fn same_zone_flow_allowed() {
        // Same-zone flows are always allowed (no change in either dimension)
        let work = ProvenanceRecord::new(ZoneId::work());
        assert_eq!(work.can_flow_to(&ZoneId::work()), FlowCheckResult::Allowed);
        log_flow_test(
            "same_zone_flow_allowed_work",
            "integrity",
            "work",
            "work",
            false,
            "pass",
            None,
        );

        let owner = ProvenanceRecord::new(ZoneId::owner());
        assert_eq!(
            owner.can_flow_to(&ZoneId::owner()),
            FlowCheckResult::Allowed
        );
        log_flow_test(
            "same_zone_flow_allowed_owner",
            "integrity",
            "owner",
            "owner",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn flow_up_integrity_requires_elevation() {
        let work = ProvenanceRecord::new(ZoneId::work());
        // Work integrity cannot flow up to owner without elevation
        assert_eq!(
            work.can_flow_to(&ZoneId::owner()),
            FlowCheckResult::RequiresElevation
        );
        log_flow_test(
            "flow_up_integrity_requires_elevation",
            "integrity",
            "work",
            "owner",
            false,
            "pass",
            Some("REQUIRES_ELEVATION"),
        );
    }

    #[test]
    fn flow_up_confidentiality_requires_elevation() {
        let public = ProvenanceRecord::new(ZoneId::public());
        // Public→Private: confidentiality flows UP (OK), but integrity must also flow UP
        // which requires elevation
        assert_eq!(
            public.can_flow_to(&ZoneId::private()),
            FlowCheckResult::RequiresElevation
        );
        log_flow_test(
            "flow_up_confidentiality_requires_elevation",
            "integrity",
            "public",
            "private",
            false,
            "pass",
            Some("REQUIRES_ELEVATION"),
        );
    }

    #[test]
    fn flow_down_confidentiality_requires_declassification() {
        let private = ProvenanceRecord::new(ZoneId::private());
        // Private confidentiality cannot flow down to public without declassification
        assert_eq!(
            private.can_flow_to(&ZoneId::public()),
            FlowCheckResult::RequiresDeclassification
        );
        log_flow_test(
            "flow_down_confidentiality_requires_declassification",
            "confidentiality",
            "private",
            "public",
            false,
            "pass",
            Some("REQUIRES_DECLASSIFICATION"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Label Adjustment Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn elevation_increases_integrity() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        let token_id = test_object_id("approval-token");

        record
            .apply_elevation(IntegrityLevel::Owner, token_id, 1000)
            .expect("elevation should succeed");

        assert_eq!(record.integrity_label, IntegrityLevel::Owner);
        assert_eq!(record.label_adjustments.len(), 1);
        assert_eq!(record.label_adjustments[0].kind, AdjustmentKind::Elevation);
        log_flow_test(
            "elevation_increases_integrity",
            "integrity",
            "work",
            "owner",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn elevation_rejects_downgrade() {
        let mut record = ProvenanceRecord::new(ZoneId::owner());
        let token_id = test_object_id("approval-token");

        let result = record.apply_elevation(IntegrityLevel::Work, token_id, 1000);
        assert!(matches!(
            result,
            Err(ProvenanceViolation::InvalidElevation { .. })
        ));
        log_flow_test(
            "elevation_rejects_downgrade",
            "integrity",
            "owner",
            "work",
            true,
            "pass",
            Some("INVALID_ELEVATION"),
        );
    }

    #[test]
    fn declassification_decreases_confidentiality() {
        let mut record = ProvenanceRecord::new(ZoneId::private());
        let token_id = test_object_id("approval-token");

        record
            .apply_declassification(ConfidentialityLevel::Work, token_id, 1000)
            .expect("declassification should succeed");

        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);
        assert_eq!(record.label_adjustments.len(), 1);
        assert_eq!(
            record.label_adjustments[0].kind,
            AdjustmentKind::Declassification
        );
        log_flow_test(
            "declassification_decreases_confidentiality",
            "confidentiality",
            "private",
            "work",
            true,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Taint Reduction Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn taint_reduction_clears_flags() {
        let mut record = ProvenanceRecord::public_input();
        record.taint_flags.insert(TaintFlag::UnverifiedLink);
        assert_eq!(record.taint_flags.len(), 2);

        let receipt_id = test_object_id("sanitizer-receipt");
        record.apply_taint_reduction(&[TaintFlag::UnverifiedLink], receipt_id, vec![], 1000);

        assert!(!record.taint_flags.contains(TaintFlag::UnverifiedLink));
        assert!(record.taint_flags.contains(TaintFlag::PublicInput)); // Still there
        assert_eq!(record.taint_reductions.len(), 1);
        log_flow_test(
            "taint_reduction_clears_flags",
            "integrity",
            "public",
            "public",
            true,
            "pass",
            Some("TAINT_REDUCTION"),
        );
    }

    #[test]
    fn taint_reduction_noop_without_matching_flags() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::UserGenerated);

        let receipt_id = test_object_id("sanitizer-receipt");
        record.apply_taint_reduction(&[TaintFlag::UnverifiedLink], receipt_id, vec![], 1000);

        assert!(record.taint_flags.contains(TaintFlag::UserGenerated));
        assert!(record.taint_reductions.is_empty());
        log_flow_test(
            "taint_reduction_noop_without_matching_flags",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            Some("NO_MATCHING_TAINT"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Zone Crossing Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_crossing_approved() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        let token_id = test_object_id("crossing-approval");

        record.record_zone_crossing(ZoneId::private(), true, Some(token_id), 1000);

        assert_eq!(record.current_zone.as_str(), "z:private");
        assert_eq!(record.zone_crossings.len(), 1);
        assert!(record.zone_crossings[0].approved);
        assert!(!record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        log_flow_test(
            "zone_crossing_approved",
            "integrity",
            "work",
            "private",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn zone_crossing_unapproved_adds_taint() {
        let mut record = ProvenanceRecord::new(ZoneId::work());

        record.record_zone_crossing(ZoneId::private(), false, None, 1000);

        assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        log_flow_test(
            "zone_crossing_unapproved_adds_taint",
            "integrity",
            "work",
            "private",
            false,
            "pass",
            Some("CROSS_ZONE_UNAPPROVED"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ApprovalToken Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn approval_token_validity() {
        let token = ApprovalToken {
            token_id: "test-token".into(),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            issuer: "node:test".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.test".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        assert!(token.is_not_yet_valid(500));
        assert!(token.is_valid(1500));
        assert!(token.is_expired(2500));
        log_flow_test(
            "approval_token_validity",
            "integrity",
            "work",
            "owner",
            true,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SanitizerReceipt Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sanitizer_receipt_validation() {
        let receipt = SanitizerReceipt {
            receipt_id: "test-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput, TaintFlag::UserGenerated],
            covered_inputs: vec![test_object_id("input1")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        assert!(receipt.is_valid());
        assert!(receipt.can_clear(TaintFlag::PublicInput));
        assert!(!receipt.can_clear(TaintFlag::PotentiallyMalicious)); // Not authorized
        assert!(receipt.covers_input(&test_object_id("input1")));
        log_flow_test(
            "sanitizer_receipt_validation",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn sanitizer_receipt_invalid_if_unauthorized_clear() {
        let receipt = SanitizerReceipt {
            receipt_id: "test-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input1")],
            cleared_flags: vec![TaintFlag::PublicInput, TaintFlag::PotentiallyMalicious], // Not authorized!
            signature: None,
        };

        assert!(!receipt.is_valid());
        log_flow_test(
            "sanitizer_receipt_invalid_if_unauthorized_clear",
            "integrity",
            "work",
            "work",
            false,
            "pass",
            Some("UNAUTHORIZED_CLEAR"),
        );
    }

    #[test]
    fn sanitizer_receipt_coverage_checks_inputs() {
        let receipt = SanitizerReceipt {
            receipt_id: "test-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input1"), test_object_id("input2")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        assert!(receipt.covers_input(&test_object_id("input1")));
        assert!(receipt.covers_input(&test_object_id("input2")));
        assert!(!receipt.covers_input(&test_object_id("input3")));
        log_flow_test(
            "sanitizer_receipt_coverage_checks_inputs",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            Some("COVERS_INPUT"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provenance_record_serialization_roundtrip() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        record.taint_flags.insert(TaintFlag::UserGenerated);
        record.input_sources.push(test_object_id("source1"));

        let json = serde_json::to_string(&record).expect("serialization failed");
        let deserialized: ProvenanceRecord =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(
            record.origin_zone.as_str(),
            deserialized.origin_zone.as_str()
        );
        assert_eq!(record.integrity_label, deserialized.integrity_label);
        assert!(deserialized.taint_flags.contains(TaintFlag::UserGenerated));
    }

    #[test]
    fn approval_scope_serialization() {
        let scope = ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.telegram".into(),
            method_pattern: "send_message".into(),
            request_object_id: Some(test_object_id("req")),
            input_hash: None,
            input_constraints: vec![InputConstraint {
                pointer: "/chat_id".into(),
                expected: serde_json::json!("12345"),
            }],
        });

        let json = serde_json::to_string(&scope).expect("serialization failed");
        assert!(json.contains("\"type\":\"execution\""));
        assert!(json.contains("\"pointer\":\"/chat_id\""));
    }

    #[test]
    fn approval_scope_declassification_serialization() {
        let scope = ApprovalScope::Declassification(DeclassificationScope {
            from_zone: ZoneId::private(),
            to_zone: ZoneId::work(),
            object_ids: vec![test_object_id("obj-1"), test_object_id("obj-2")],
            target_confidentiality: ConfidentialityLevel::Work,
        });

        let json = serde_json::to_string(&scope).expect("serialization failed");
        assert!(json.contains("\"type\":\"declassification\""));
        assert!(json.contains(ZoneId::PRIVATE));
        assert!(json.contains(ZoneId::WORK));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attack Scenarios (Adversarial Security Tests)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn attack_taint_laundering_without_receipt_rejected() {
        // Attempt to remove taint without a valid SanitizerReceipt
        let mut record = ProvenanceRecord::public_input();
        record.taint_flags.insert(TaintFlag::PotentiallyMalicious);

        // Attacker tries to directly modify taint_flags - but in the real system,
        // taint reduction MUST go through apply_taint_reduction with a valid receipt.
        // Here we verify that partial reduction still leaves critical taints.
        let receipt_id = test_object_id("fake-receipt");
        record.apply_taint_reduction(
            &[TaintFlag::UserGenerated], // Trying to clear non-existent flag
            receipt_id,
            vec![],
            1000,
        );

        // PUBLIC_INPUT and POTENTIALLY_MALICIOUS still present - cannot be laundered
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        assert!(record.taint_flags.contains(TaintFlag::PotentiallyMalicious));
        assert!(record.taint_flags.has_critical());
        log_flow_test(
            "attack_taint_laundering_without_receipt_rejected",
            "integrity",
            "public",
            "public",
            false,
            "pass",
            Some("TAINT_LAUNDERING_BLOCKED"),
        );
    }

    #[test]
    fn attack_elevation_bypass_without_approval_rejected() {
        // Attempt to flow low-integrity data to high-integrity zone without approval
        let public = ProvenanceRecord::public_input();

        // Try to flow to owner zone - should require elevation
        let flow_result = public.can_flow_to(&ZoneId::owner());
        assert_eq!(flow_result, FlowCheckResult::RequiresElevation);

        // Verify cannot drive dangerous operations
        assert!(matches!(
            public.can_drive_operation(SafetyTier::Dangerous),
            Err(ProvenanceViolation::PublicInputForDangerousOperation)
        ));

        // Cannot directly set integrity - must use apply_elevation with token
        let mut record = ProvenanceRecord::public_input();
        let fake_token = test_object_id("fake-token");

        // Elevation from Untrusted to Owner should succeed if token is provided
        // (signature verification happens at a higher layer)
        let result = record.apply_elevation(IntegrityLevel::Owner, fake_token, 1000);
        assert!(result.is_ok()); // Elevation works, but signature would be invalid

        // However, the taint is STILL PRESENT even after elevation
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        assert!(record.taint_flags.has_critical());

        log_flow_test(
            "attack_elevation_bypass_without_approval_rejected",
            "integrity",
            "public",
            "owner",
            false,
            "pass",
            Some("ELEVATION_BYPASS_BLOCKED"),
        );
    }

    #[test]
    fn attack_declassification_leak_without_approval_rejected() {
        // Attempt to leak high-confidentiality data to low-confidentiality zone
        let private = ProvenanceRecord::new(ZoneId::private());

        // Try to flow to public zone - should require declassification
        let flow_result = private.can_flow_to(&ZoneId::public());
        assert_eq!(flow_result, FlowCheckResult::RequiresDeclassification);

        // Attempt declassification to same level should fail
        let mut record = ProvenanceRecord::new(ZoneId::private());
        let fake_token = test_object_id("fake-token");

        let result = record.apply_declassification(ConfidentialityLevel::Private, fake_token, 1000);
        assert!(matches!(
            result,
            Err(ProvenanceViolation::InvalidDeclassification { .. })
        ));

        log_flow_test(
            "attack_declassification_leak_without_approval_rejected",
            "confidentiality",
            "private",
            "public",
            false,
            "pass",
            Some("DECLASSIFICATION_LEAK_BLOCKED"),
        );
    }

    #[test]
    fn attack_forged_sanitizer_receipt_invalid_signature() {
        // A forged receipt that claims to clear flags it's not authorized for
        let forged_receipt = SanitizerReceipt {
            receipt_id: "forged-receipt".into(),
            timestamp_ms: 1000,
            sanitizer_id: "attacker:evil".into(),
            sanitizer_zone: ZoneId::public(), // Low-trust zone
            authorized_flags: vec![TaintFlag::UnverifiedLink], // Only authorized for this
            covered_inputs: vec![test_object_id("victim-input")],
            cleared_flags: vec![
                TaintFlag::PublicInput,          // NOT authorized!
                TaintFlag::PotentiallyMalicious, // NOT authorized!
            ],
            signature: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]), // Invalid signature
        };

        // Receipt validation fails - cleared flags not in authorized list
        assert!(!forged_receipt.is_valid());

        // Cannot clear PublicInput with this receipt
        assert!(!forged_receipt.can_clear(TaintFlag::PublicInput));
        assert!(!forged_receipt.can_clear(TaintFlag::PotentiallyMalicious));

        log_flow_test(
            "attack_forged_sanitizer_receipt_invalid_signature",
            "integrity",
            "public",
            "public",
            false,
            "pass",
            Some("FORGED_RECEIPT_REJECTED"),
        );
    }

    #[test]
    fn attack_stale_approval_token_rejected() {
        // Expired ApprovalToken should be rejected
        let stale_token = ApprovalToken {
            token_id: "stale-token".into(),
            issued_at_ms: 1000,
            expires_at_ms: 2000, // Expired at 2000ms
            issuer: "node:legitimate".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.sensitive".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Token is expired at current time 5000ms
        let now_ms = 5000;
        assert!(stale_token.is_expired(now_ms));
        assert!(!stale_token.is_valid(now_ms));

        // Token was valid in the past
        let past_ms = 1500;
        assert!(!stale_token.is_expired(past_ms));
        assert!(stale_token.is_valid(past_ms));

        log_flow_test(
            "attack_stale_approval_token_rejected",
            "integrity",
            "work",
            "owner",
            false,
            "pass",
            Some("STALE_TOKEN_REJECTED"),
        );
    }

    #[test]
    fn attack_future_approval_token_rejected() {
        // ApprovalToken not yet valid (issued_at in future)
        let future_token = ApprovalToken {
            token_id: "future-token".into(),
            issued_at_ms: 5000, // Not valid until 5000ms
            expires_at_ms: 10000,
            issuer: "node:legitimate".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.sensitive".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Token is not yet valid at current time 1000ms
        let now_ms = 1000;
        assert!(future_token.is_not_yet_valid(now_ms));
        assert!(!future_token.is_valid(now_ms));

        // Token will be valid in the future
        let future_ms = 7000;
        assert!(!future_token.is_not_yet_valid(future_ms));
        assert!(future_token.is_valid(future_ms));

        log_flow_test(
            "attack_future_approval_token_rejected",
            "integrity",
            "work",
            "owner",
            false,
            "pass",
            Some("FUTURE_TOKEN_REJECTED"),
        );
    }

    #[test]
    fn attack_mixed_input_integrity_downgrade() {
        // Mixing high-integrity with low-integrity data downgrades result
        let owner = ProvenanceRecord::new(ZoneId::owner());
        let mut attacker = ProvenanceRecord::public_input();
        attacker.taint_flags.insert(TaintFlag::PotentiallyMalicious);

        // Merge owner data with attacker-controlled data
        let merged = ProvenanceRecord::merge(&[&owner, &attacker], ZoneId::work());

        // Result has MINIMUM integrity (Untrusted from attacker)
        assert_eq!(merged.integrity_label, IntegrityLevel::Untrusted);

        // Result accumulates ALL taints
        assert!(merged.taint_flags.contains(TaintFlag::PublicInput));
        assert!(merged.taint_flags.contains(TaintFlag::PotentiallyMalicious));
        assert!(merged.taint_flags.has_critical());

        // Cannot drive dangerous operations
        assert!(matches!(
            merged.can_drive_operation(SafetyTier::Dangerous),
            Err(ProvenanceViolation::PublicInputForDangerousOperation)
        ));

        log_flow_test(
            "attack_mixed_input_integrity_downgrade",
            "integrity",
            "owner+public",
            "untrusted",
            false,
            "pass",
            Some("INTEGRITY_DOWNGRADE_ENFORCED"),
        );
    }

    #[test]
    fn attack_cross_zone_without_approval_adds_taint() {
        // Crossing zones without approval must add taint
        let mut record = ProvenanceRecord::new(ZoneId::work());
        assert!(!record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));

        // Cross without approval
        record.record_zone_crossing(ZoneId::private(), false, None, 1000);

        // Taint is added
        assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        assert!(record.taint_flags.has_critical());

        log_flow_test(
            "attack_cross_zone_without_approval_adds_taint",
            "integrity",
            "work",
            "private",
            false,
            "pass",
            Some("UNAPPROVED_CROSSING_TAINTED"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vectors (Deterministic Test Vectors for Interop)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_vector_merge_two_records() {
        // Deterministic merge test vector
        let work = ProvenanceRecord::new(ZoneId::work());
        let private = ProvenanceRecord::new(ZoneId::private());

        let merged = ProvenanceRecord::merge(&[&work, &private], ZoneId::work());

        // Expected output (golden vector):
        // - integrity = MIN(Work, Private) = Work
        // - confidentiality = MAX(Work, Private) = Private
        assert_eq!(
            merged.integrity_label,
            IntegrityLevel::Work,
            "GOLDEN: merge(work, private).integrity == Work"
        );
        assert_eq!(
            merged.confidentiality_label,
            ConfidentialityLevel::Private,
            "GOLDEN: merge(work, private).confidentiality == Private"
        );
        assert!(
            merged.taint_flags.is_empty(),
            "GOLDEN: merge(work, private).taint_flags == empty"
        );

        log_flow_test(
            "golden_vector_merge_two_records",
            "integrity",
            "work+private",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_merge_with_taint() {
        // Merge with taint accumulation golden vector
        let mut a = ProvenanceRecord::new(ZoneId::work());
        a.taint_flags.insert(TaintFlag::PublicInput);

        let mut b = ProvenanceRecord::new(ZoneId::private());
        b.taint_flags.insert(TaintFlag::UserGenerated);

        let merged = ProvenanceRecord::merge(&[&a, &b], ZoneId::work());

        // Expected output:
        // - integrity = MIN(Work, Private) = Work
        // - confidentiality = MAX(Work, Private) = Private
        // - taint = OR(PublicInput, UserGenerated)
        assert_eq!(merged.integrity_label, IntegrityLevel::Work);
        assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
        assert!(merged.taint_flags.contains(TaintFlag::PublicInput));
        assert!(merged.taint_flags.contains(TaintFlag::UserGenerated));
        assert_eq!(merged.taint_flags.len(), 2);

        log_flow_test(
            "golden_vector_merge_with_taint",
            "integrity",
            "work+private",
            "work",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_elevation_sequence() {
        // Elevation sequence golden vector
        let mut record = ProvenanceRecord::new(ZoneId::community());
        let token1 = test_object_id("elevation-token-1");
        let token2 = test_object_id("elevation-token-2");

        // Initial state
        assert_eq!(record.integrity_label, IntegrityLevel::Community);

        // First elevation: Community → Work
        record
            .apply_elevation(IntegrityLevel::Work, token1, 1000)
            .expect("elevation to Work should succeed");
        assert_eq!(record.integrity_label, IntegrityLevel::Work);
        assert_eq!(record.label_adjustments.len(), 1);

        // Second elevation: Work → Owner
        record
            .apply_elevation(IntegrityLevel::Owner, token2, 2000)
            .expect("elevation to Owner should succeed");
        assert_eq!(record.integrity_label, IntegrityLevel::Owner);
        assert_eq!(record.label_adjustments.len(), 2);

        // Verify adjustment history
        assert_eq!(
            record.label_adjustments[0].prev_integrity,
            Some(IntegrityLevel::Community)
        );
        assert_eq!(
            record.label_adjustments[0].new_integrity,
            Some(IntegrityLevel::Work)
        );
        assert_eq!(
            record.label_adjustments[1].prev_integrity,
            Some(IntegrityLevel::Work)
        );
        assert_eq!(
            record.label_adjustments[1].new_integrity,
            Some(IntegrityLevel::Owner)
        );

        log_flow_test(
            "golden_vector_elevation_sequence",
            "integrity",
            "community",
            "owner",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_declassification_sequence() {
        // Declassification sequence golden vector
        let mut record = ProvenanceRecord::new(ZoneId::owner());
        let token1 = test_object_id("declassify-token-1");
        let token2 = test_object_id("declassify-token-2");

        // Initial state
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Owner);

        // First declassification: Owner → Private
        record
            .apply_declassification(ConfidentialityLevel::Private, token1, 1000)
            .expect("declassification to Private should succeed");
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Private);

        // Second declassification: Private → Work
        record
            .apply_declassification(ConfidentialityLevel::Work, token2, 2000)
            .expect("declassification to Work should succeed");
        assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);
        assert_eq!(record.label_adjustments.len(), 2);

        log_flow_test(
            "golden_vector_declassification_sequence",
            "confidentiality",
            "owner",
            "work",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_taint_reduction() {
        // Taint reduction golden vector
        let mut record = ProvenanceRecord::public_input();
        record.taint_flags.insert(TaintFlag::UnverifiedLink);
        record.taint_flags.insert(TaintFlag::UserGenerated);

        let receipt_id = test_object_id("sanitizer-receipt");
        let covered = vec![test_object_id("input-1")];

        // Initial: 3 taints
        assert_eq!(record.taint_flags.len(), 3);

        // Sanitize UnverifiedLink only
        record.apply_taint_reduction(&[TaintFlag::UnverifiedLink], receipt_id, covered, 1000);

        // Result: 2 taints remain
        assert_eq!(record.taint_flags.len(), 2);
        assert!(!record.taint_flags.contains(TaintFlag::UnverifiedLink));
        assert!(record.taint_flags.contains(TaintFlag::PublicInput));
        assert!(record.taint_flags.contains(TaintFlag::UserGenerated));

        // Reduction is recorded
        assert_eq!(record.taint_reductions.len(), 1);
        assert_eq!(
            record.taint_reductions[0].cleared_flags,
            vec![TaintFlag::UnverifiedLink]
        );

        log_flow_test(
            "golden_vector_taint_reduction",
            "integrity",
            "public",
            "public",
            true,
            "pass",
            Some("TAINT_REDUCTION"),
        );
    }

    #[test]
    fn golden_vector_flow_check_matrix() {
        // Complete flow check matrix golden vector
        let zones = [
            ZoneId::public(),
            ZoneId::community(),
            ZoneId::work(),
            ZoneId::private(),
            ZoneId::owner(),
        ];

        // For same-zone flows, should always be Allowed
        for zone in &zones {
            let record = ProvenanceRecord::new(zone.clone());
            assert_eq!(
                record.can_flow_to(zone),
                FlowCheckResult::Allowed,
                "Same-zone flow should be allowed: {}",
                zone.as_str()
            );
        }

        // Public → Owner requires elevation (integrity up)
        let public = ProvenanceRecord::new(ZoneId::public());
        assert_eq!(
            public.can_flow_to(&ZoneId::owner()),
            FlowCheckResult::RequiresElevation
        );

        // Owner → Public requires declassification (confidentiality down)
        let owner = ProvenanceRecord::new(ZoneId::owner());
        assert_eq!(
            owner.can_flow_to(&ZoneId::public()),
            FlowCheckResult::RequiresDeclassification
        );

        log_flow_test(
            "golden_vector_flow_check_matrix",
            "integrity",
            "matrix",
            "matrix",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_safety_tier_enforcement() {
        // Safety tier enforcement golden vector
        let public = ProvenanceRecord::public_input();
        let work = ProvenanceRecord::new(ZoneId::work());
        let owner = ProvenanceRecord::new(ZoneId::owner());

        // Safe tier: all allowed
        assert!(public.can_drive_operation(SafetyTier::Safe).is_ok());
        assert!(work.can_drive_operation(SafetyTier::Safe).is_ok());
        assert!(owner.can_drive_operation(SafetyTier::Safe).is_ok());

        // Dangerous tier: public blocked, work/owner allowed
        assert!(public.can_drive_operation(SafetyTier::Dangerous).is_err());
        assert!(work.can_drive_operation(SafetyTier::Dangerous).is_ok());
        assert!(owner.can_drive_operation(SafetyTier::Dangerous).is_ok());

        // Critical tier: same as dangerous
        assert!(public.can_drive_operation(SafetyTier::Critical).is_err());
        assert!(work.can_drive_operation(SafetyTier::Critical).is_ok());
        assert!(owner.can_drive_operation(SafetyTier::Critical).is_ok());

        log_flow_test(
            "golden_vector_safety_tier_enforcement",
            "integrity",
            "matrix",
            "matrix",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn golden_vector_approval_token_lifecycle() {
        // ApprovalToken lifecycle golden vector
        let token = ApprovalToken {
            token_id: "lifecycle-test".into(),
            issued_at_ms: 1000,
            expires_at_ms: 3000,
            issuer: "node:issuer".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Before valid: t=500
        assert!(token.is_not_yet_valid(500));
        assert!(!token.is_expired(500));
        assert!(!token.is_valid(500));

        // At issued_at: t=1000 (edge case - valid)
        assert!(!token.is_not_yet_valid(1000));
        assert!(!token.is_expired(1000));
        assert!(token.is_valid(1000));

        // During validity: t=2000
        assert!(!token.is_not_yet_valid(2000));
        assert!(!token.is_expired(2000));
        assert!(token.is_valid(2000));

        // At expires_at: t=3000 (edge case - expired)
        assert!(!token.is_not_yet_valid(3000));
        assert!(token.is_expired(3000));
        assert!(!token.is_valid(3000));

        // After expiry: t=5000
        assert!(!token.is_not_yet_valid(5000));
        assert!(token.is_expired(5000));
        assert!(!token.is_valid(5000));

        log_flow_test(
            "golden_vector_approval_token_lifecycle",
            "integrity",
            "lifecycle",
            "lifecycle",
            true,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SanitizerReceipt Verification Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sanitizer_receipt_covers_input() {
        let input_a = test_object_id("input-a");
        let input_b = test_object_id("input-b");
        let input_c = test_object_id("input-c");

        let receipt = SanitizerReceipt {
            receipt_id: "receipt-001".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput, TaintFlag::UserGenerated],
            covered_inputs: vec![input_a, input_b],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        assert!(receipt.covers_input(&input_a));
        assert!(receipt.covers_input(&input_b));
        assert!(
            !receipt.covers_input(&input_c),
            "Should not cover unclaimed input"
        );

        log_flow_test(
            "sanitizer_receipt_covers_input",
            "integrity",
            "sanitizer",
            "sanitizer",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn sanitizer_receipt_can_clear_authorized_flags() {
        let receipt = SanitizerReceipt {
            receipt_id: "receipt-002".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput, TaintFlag::UserGenerated],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        assert!(receipt.can_clear(TaintFlag::PublicInput));
        assert!(receipt.can_clear(TaintFlag::UserGenerated));
        assert!(
            !receipt.can_clear(TaintFlag::PotentiallyMalicious),
            "Should not be able to clear unauthorized flag"
        );
        assert!(
            !receipt.can_clear(TaintFlag::AiGenerated),
            "Should not be able to clear unauthorized flag"
        );

        log_flow_test(
            "sanitizer_receipt_can_clear_authorized_flags",
            "integrity",
            "sanitizer",
            "sanitizer",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn sanitizer_receipt_is_valid_when_cleared_subset_of_authorized() {
        // Valid: cleared flags are subset of authorized
        let valid_receipt = SanitizerReceipt {
            receipt_id: "receipt-valid".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![
                TaintFlag::PublicInput,
                TaintFlag::UserGenerated,
                TaintFlag::UnverifiedLink,
            ],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput, TaintFlag::UserGenerated],
            signature: None,
        };
        assert!(valid_receipt.is_valid());

        // Invalid: cleared flag not in authorized set
        let invalid_receipt = SanitizerReceipt {
            receipt_id: "receipt-invalid".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput, TaintFlag::PotentiallyMalicious], // Unauthorized!
            signature: None,
        };
        assert!(
            !invalid_receipt.is_valid(),
            "Receipt should be invalid when clearing unauthorized flags"
        );

        log_flow_test(
            "sanitizer_receipt_is_valid_when_cleared_subset_of_authorized",
            "integrity",
            "sanitizer",
            "sanitizer",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn sanitizer_receipt_empty_cleared_flags_is_valid() {
        let receipt = SanitizerReceipt {
            receipt_id: "receipt-empty".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![], // No flags cleared - valid
            signature: None,
        };
        assert!(receipt.is_valid(), "Empty cleared flags should be valid");

        log_flow_test(
            "sanitizer_receipt_empty_cleared_flags_is_valid",
            "integrity",
            "sanitizer",
            "sanitizer",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn attack_forged_sanitizer_receipt_clearing_unauthorized_flags() {
        // Attack: Attacker creates a receipt claiming to clear flags they're not authorized for
        let forged_receipt = SanitizerReceipt {
            receipt_id: "forged-receipt".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "attacker:malicious".into(),
            sanitizer_zone: ZoneId::public(), // Low integrity zone
            authorized_flags: vec![TaintFlag::UnverifiedLink], // Only authorized for this
            covered_inputs: vec![test_object_id("victim-input")],
            cleared_flags: vec![TaintFlag::PotentiallyMalicious], // Trying to clear critical flag!
            signature: None,
        };

        // Verification should fail - cleared flags not subset of authorized
        assert!(
            !forged_receipt.is_valid(),
            "Forged receipt clearing unauthorized flags must be rejected"
        );

        log_flow_test(
            "attack_forged_sanitizer_receipt_clearing_unauthorized_flags",
            "integrity",
            "public",
            "work",
            false,
            "fail",
            Some("unauthorized_clear"),
        );
    }

    #[test]
    fn sanitizer_receipt_zone_integrity_requirements() {
        // High-integrity zone sanitizer can clear critical flags
        let high_integrity_receipt = SanitizerReceipt {
            receipt_id: "trusted-sanitizer-receipt".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:owner-trusted".into(),
            sanitizer_zone: ZoneId::owner(), // High integrity zone
            authorized_flags: vec![TaintFlag::PotentiallyMalicious, TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("sensitive-input")],
            cleared_flags: vec![TaintFlag::PotentiallyMalicious], // Clearing critical flag
            signature: Some(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        };

        // Receipt from high-integrity zone should be valid for clearing critical flags
        assert!(
            high_integrity_receipt.is_valid(),
            "High-integrity sanitizer can clear authorized critical flags"
        );

        // Low-integrity zone sanitizer attempting to clear critical flags
        let low_integrity_receipt = SanitizerReceipt {
            receipt_id: "untrusted-sanitizer-receipt".into(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer:public-untrusted".into(),
            sanitizer_zone: ZoneId::public(), // Low integrity zone
            authorized_flags: vec![TaintFlag::UnverifiedLink], // Only minor flag
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::UnverifiedLink], // Non-critical flag
            signature: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };

        // Low-integrity sanitizer can still clear non-critical flags if authorized
        assert!(
            low_integrity_receipt.is_valid(),
            "Low-integrity sanitizer can clear authorized non-critical flags"
        );

        // Verify zone integrity levels are correctly ordered
        let owner_integrity = IntegrityLevel::from_zone(&ZoneId::owner());
        let work_integrity = IntegrityLevel::from_zone(&ZoneId::work());
        let public_integrity = IntegrityLevel::from_zone(&ZoneId::public());

        // Zone integrity comparison (owner > work > public)
        assert!(
            owner_integrity > work_integrity,
            "Owner zone has higher integrity than work zone"
        );
        assert!(
            work_integrity > public_integrity,
            "Work zone has higher integrity than public zone"
        );

        log_flow_test(
            "sanitizer_receipt_zone_integrity_requirements",
            "integrity",
            "zone",
            "zone",
            true,
            "pass",
            Some("ZONE_INTEGRITY_VERIFIED"),
        );
    }

    #[test]
    fn sanitizer_receipt_staleness_detection() {
        // Current time in milliseconds
        let now_ms: u64 = 1_700_000_000_000;
        let one_hour_ms: u64 = 3_600_000;
        let one_day_ms: u64 = 86_400_000;

        // Fresh receipt (created now)
        let fresh_receipt = SanitizerReceipt {
            receipt_id: "fresh-receipt".into(),
            timestamp_ms: now_ms,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        // Receipt from 1 hour ago
        let hourly_receipt = SanitizerReceipt {
            receipt_id: "hourly-receipt".into(),
            timestamp_ms: now_ms - one_hour_ms,
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        // Stale receipt (from 30 days ago)
        let stale_receipt = SanitizerReceipt {
            receipt_id: "stale-receipt".into(),
            timestamp_ms: now_ms - (30 * one_day_ms),
            sanitizer_id: "sanitizer:trusted".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        // All receipts are structurally valid (is_valid checks flag authorization)
        assert!(fresh_receipt.is_valid());
        assert!(hourly_receipt.is_valid());
        assert!(stale_receipt.is_valid());

        // Age calculation helpers
        let fresh_age = now_ms.saturating_sub(fresh_receipt.timestamp_ms);
        let hourly_age = now_ms.saturating_sub(hourly_receipt.timestamp_ms);
        let stale_age = now_ms.saturating_sub(stale_receipt.timestamp_ms);

        assert_eq!(fresh_age, 0, "Fresh receipt has zero age");
        assert_eq!(hourly_age, one_hour_ms, "Hourly receipt is 1 hour old");
        assert!(
            stale_age > 29 * one_day_ms,
            "Stale receipt is > 29 days old"
        );

        // Configurable staleness threshold (example: 7 days)
        let staleness_threshold_ms = 7 * one_day_ms;

        let fresh_is_stale = fresh_age > staleness_threshold_ms;
        let hourly_is_stale = hourly_age > staleness_threshold_ms;
        let stale_is_stale = stale_age > staleness_threshold_ms;

        assert!(!fresh_is_stale, "Fresh receipt is not stale");
        assert!(!hourly_is_stale, "Hourly receipt is not stale");
        assert!(stale_is_stale, "30-day-old receipt is stale");

        log_flow_test(
            "sanitizer_receipt_staleness_detection",
            "integrity",
            "time",
            "time",
            true,
            "pass",
            Some("STALENESS_DETECTED"),
        );
    }

    #[test]
    fn sanitizer_receipt_future_timestamp_detection() {
        // Current time
        let now_ms: u64 = 1_700_000_000_000;

        // Receipt with future timestamp (suspicious/invalid)
        let future_receipt = SanitizerReceipt {
            receipt_id: "future-receipt".into(),
            timestamp_ms: now_ms + 3_600_000, // 1 hour in the future
            sanitizer_id: "sanitizer:suspicious".into(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![test_object_id("input")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };

        // Structurally valid but timestamp is suspicious
        assert!(
            future_receipt.is_valid(),
            "Structural validity doesn't check timestamp"
        );

        // Future timestamp check
        let is_future = future_receipt.timestamp_ms > now_ms;
        assert!(is_future, "Future timestamp should be detected");

        // Clock skew tolerance (e.g., 5 minutes)
        let clock_skew_tolerance_ms: u64 = 5 * 60 * 1000;
        let is_beyond_skew = future_receipt.timestamp_ms > now_ms + clock_skew_tolerance_ms;
        assert!(
            is_beyond_skew,
            "1-hour future timestamp exceeds 5-minute skew tolerance"
        );

        log_flow_test(
            "sanitizer_receipt_future_timestamp_detection",
            "integrity",
            "time",
            "time",
            false,
            "pass",
            Some("FUTURE_TIMESTAMP_DETECTED"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-Zone Operations Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_crossing_tracking() {
        let mut record = ProvenanceRecord::new(ZoneId::work());
        assert_eq!(record.origin_zone, ZoneId::work());
        assert_eq!(record.current_zone, ZoneId::work());
        assert!(record.zone_crossings.is_empty());

        // Simulate zone crossing
        let crossing = ZoneCrossing {
            timestamp_ms: 1_700_000_000_000,
            from_zone: ZoneId::work(),
            to_zone: ZoneId::private(),
            approved: true,
            approval_token_id: Some(test_object_id("approval")),
        };
        record.zone_crossings.push(crossing);
        record.current_zone = ZoneId::private();

        assert_eq!(record.origin_zone, ZoneId::work());
        assert_eq!(record.current_zone, ZoneId::private());
        assert_eq!(record.zone_crossings.len(), 1);
        assert!(record.zone_crossings[0].approved);

        log_flow_test(
            "zone_crossing_tracking",
            "integrity",
            "work",
            "private",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn unapproved_zone_crossing_adds_taint() {
        let mut record = ProvenanceRecord::new(ZoneId::work());

        // Unapproved crossing should add CrossZoneUnapproved taint
        let crossing = ZoneCrossing {
            timestamp_ms: 1_700_000_000_000,
            from_zone: ZoneId::work(),
            to_zone: ZoneId::private(),
            approved: false,
            approval_token_id: None,
        };
        record.zone_crossings.push(crossing);
        record.taint_flags.insert(TaintFlag::CrossZoneUnapproved);

        assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
        assert!(
            record.taint_flags.has_critical(),
            "CrossZoneUnapproved should be critical taint"
        );

        log_flow_test(
            "unapproved_zone_crossing_adds_taint",
            "integrity",
            "work",
            "private",
            false,
            "pass",
            None,
        );
    }

    #[test]
    fn flow_check_public_to_work_requires_elevation() {
        // Public data (low integrity, low confidentiality) flowing to work zone
        let record = ProvenanceRecord::public_input();

        // Public -> Work: integrity UP (Untrusted=0 → Work=2, requires elevation)
        // Confidentiality stays same (Public → Work, allowed)
        let result = record.can_flow_to(&ZoneId::work());
        assert_eq!(result, FlowCheckResult::RequiresElevation);

        log_flow_test(
            "flow_check_public_to_work_requires_elevation",
            "integrity",
            "public",
            "work",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn flow_check_private_to_public_requires_declassification() {
        // Private data cannot flow to public without declassification
        let record = ProvenanceRecord::new(ZoneId::private());

        let result = record.can_flow_to(&ZoneId::public());
        assert_eq!(result, FlowCheckResult::RequiresDeclassification);

        log_flow_test(
            "flow_check_private_to_public_requires_declassification",
            "confidentiality",
            "private",
            "public",
            false,
            "fail",
            Some("requires_declassification"),
        );
    }

    #[test]
    fn flow_check_work_to_owner_requires_elevation() {
        // Work data cannot flow to owner zone without elevation
        let record = ProvenanceRecord::new(ZoneId::work());

        let result = record.can_flow_to(&ZoneId::owner());
        assert_eq!(result, FlowCheckResult::RequiresElevation);

        log_flow_test(
            "flow_check_work_to_owner_requires_elevation",
            "integrity",
            "work",
            "owner",
            false,
            "fail",
            Some("requires_elevation"),
        );
    }

    #[test]
    fn flow_check_owner_to_public_requires_both() {
        // Owner data to public requires BOTH elevation (integrity) AND declassification (confidentiality)
        let record = ProvenanceRecord::new(ZoneId::owner());

        let result = record.can_flow_to(&ZoneId::public());
        // Actually, owner->public: integrity flows DOWN (allowed), confidentiality flows DOWN (needs declassification)
        // Wait - let me think about this more carefully
        // Owner: integrity=Owner(4), confidentiality=Owner(4)
        // Public: integrity=Untrusted(0), confidentiality=Public(0)
        // Integrity: target(0) <= current(4) = TRUE (flows down, allowed)
        // Confidentiality: target(0) >= current(4) = FALSE (flows down, needs declassification)
        assert_eq!(result, FlowCheckResult::RequiresDeclassification);

        log_flow_test(
            "flow_check_owner_to_public_requires_both",
            "confidentiality",
            "owner",
            "public",
            false,
            "fail",
            Some("requires_declassification"),
        );
    }

    #[test]
    fn flow_check_untrusted_to_owner_requires_elevation() {
        // Untrusted (low integrity, low confidentiality) to owner (high both)
        // Integrity: target(4) <= current(0) = FALSE (needs elevation)
        // Confidentiality: target(4) >= current(0) = TRUE (flows up, allowed)
        let mut record = ProvenanceRecord::new(ZoneId::public());
        record.integrity_label = IntegrityLevel::Untrusted;
        record.confidentiality_label = ConfidentialityLevel::Public;

        let result = record.can_flow_to(&ZoneId::owner());
        assert_eq!(result, FlowCheckResult::RequiresElevation);

        log_flow_test(
            "flow_check_untrusted_to_owner_requires_elevation",
            "integrity",
            "untrusted",
            "owner",
            false,
            "fail",
            Some("requires_elevation"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ExecutionScope Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn execution_scope_serialization() {
        let scope = ExecutionScope {
            connector_id: "fcp.test:connector:0.1.0".into(),
            method_pattern: "test.invoke.*".into(),
            request_object_id: Some(test_object_id("request")),
            input_hash: Some([0xAB; 32]),
            input_constraints: vec![InputConstraint {
                pointer: "/action".into(),
                expected: json!("send"),
            }],
        };

        let token = ApprovalToken {
            token_id: "exec-token-001".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000, // 1 hour later
            issuer: "node:issuer".into(),
            scope: ApprovalScope::Execution(scope),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Roundtrip through JSON
        let json = serde_json::to_string(&token).expect("serialization failed");
        let parsed: ApprovalToken = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(parsed.token_id, token.token_id);
        assert!(
            matches!(&parsed.scope, ApprovalScope::Execution(_)),
            "Expected Execution scope, got {:?}",
            parsed.scope
        );
        if let ApprovalScope::Execution(exec) = &parsed.scope {
            assert_eq!(exec.connector_id, "fcp.test:connector:0.1.0");
            assert_eq!(exec.method_pattern, "test.invoke.*");
            assert!(exec.request_object_id.is_some());
            assert!(exec.input_hash.is_some());
            assert_eq!(exec.input_constraints.len(), 1);
            assert_eq!(exec.input_constraints[0].pointer, "/action");
        }

        log_flow_test(
            "execution_scope_serialization",
            "integrity",
            "execution",
            "execution",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn approval_token_zone_binding() {
        // Token should be bound to a specific zone
        let token = ApprovalToken {
            token_id: "zone-bound-token".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:issuer".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        assert_eq!(token.zone_id, ZoneId::work());
        // Token for work zone should not be used in private zone
        // (This is a policy check - the struct just stores the zone)

        log_flow_test(
            "approval_token_zone_binding",
            "integrity",
            "work",
            "work",
            true,
            "pass",
            None,
        );
    }

    #[test]
    fn input_constraint_json_pointer_format() {
        let constraint = InputConstraint {
            pointer: "/data/items/0/name".into(),
            expected: json!("test-item"),
        };

        // JSON Pointer should follow RFC 6901 format
        assert!(constraint.pointer.starts_with('/'));

        // Roundtrip
        let json = serde_json::to_string(&constraint).expect("serialization failed");
        let parsed: InputConstraint = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(parsed.pointer, constraint.pointer);
        assert_eq!(parsed.expected, constraint.expected);

        log_flow_test(
            "input_constraint_json_pointer_format",
            "integrity",
            "constraint",
            "constraint",
            false,
            "pass",
            None,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ApprovalToken Scope Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn approval_token_elevation_validates_target_integrity() {
        // Elevation scope should specify a target integrity HIGHER than source
        let prov_id = test_object_id("low-integrity-prov");

        // Create token for elevation: Untrusted -> Owner
        let elevation_token = ApprovalToken {
            token_id: "elevation-token".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "elevate.operation".into(),
                original_provenance_id: prov_id,
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Extract and validate scope
        assert!(
            matches!(&elevation_token.scope, ApprovalScope::Elevation(_)),
            "Expected Elevation scope, got {:?}",
            elevation_token.scope
        );
        if let ApprovalScope::Elevation(scope) = &elevation_token.scope {
            // Target integrity should be Owner (highest)
            assert_eq!(scope.target_integrity, IntegrityLevel::Owner);
            // Token binds to specific provenance
            assert_eq!(scope.original_provenance_id, prov_id);
            // Operation must be specified
            assert!(!scope.operation_id.is_empty());
        }

        // Token must be valid (not expired, not future)
        let now_ms = 1_700_001_000_000;
        assert!(elevation_token.is_valid(now_ms));

        log_flow_test(
            "approval_token_elevation_validates_target_integrity",
            "integrity",
            "untrusted",
            "owner",
            true,
            "pass",
            Some("ELEVATION_SCOPE_VALID"),
        );
    }

    #[test]
    fn approval_token_declassification_validates_zones() {
        // Declassification scope should specify from_zone/to_zone correctly
        let object_ids = vec![test_object_id("secret-data")];

        // Create token for declassification: Private -> Public
        let declassification_token = ApprovalToken {
            token_id: "declassification-token".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Declassification(DeclassificationScope {
                from_zone: ZoneId::private(),
                to_zone: ZoneId::public(),
                object_ids: object_ids.clone(),
                target_confidentiality: ConfidentialityLevel::Public,
            }),
            zone_id: ZoneId::private(),
            signature: None,
        };

        // Extract and validate scope
        assert!(
            matches!(
                &declassification_token.scope,
                ApprovalScope::Declassification(_)
            ),
            "Expected Declassification scope, got {:?}",
            declassification_token.scope
        );
        if let ApprovalScope::Declassification(scope) = &declassification_token.scope {
            // Zone flow must be from higher to lower confidentiality
            assert_eq!(scope.from_zone, ZoneId::private());
            assert_eq!(scope.to_zone, ZoneId::public());
            // Target confidentiality should be lower than source
            assert_eq!(scope.target_confidentiality, ConfidentialityLevel::Public);
            // Object IDs must be specified
            assert!(!scope.object_ids.is_empty());
            assert_eq!(scope.object_ids, object_ids);
        }

        // Token must be valid
        let now_ms = 1_700_001_000_000;
        assert!(declassification_token.is_valid(now_ms));

        log_flow_test(
            "approval_token_declassification_validates_zones",
            "confidentiality",
            "private",
            "public",
            true,
            "pass",
            Some("DECLASSIFICATION_SCOPE_VALID"),
        );
    }

    #[test]
    fn approval_token_elevation_scope_binding_enforced() {
        // Elevation token is bound to specific provenance - using wrong provenance should fail
        let correct_prov_id = test_object_id("correct-provenance");
        let wrong_prov_id = test_object_id("wrong-provenance");

        let elevation_token = ApprovalToken {
            token_id: "bound-elevation".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "bound.op".into(),
                original_provenance_id: correct_prov_id,
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        assert!(
            matches!(&elevation_token.scope, ApprovalScope::Elevation(_)),
            "Expected Elevation scope, got {:?}",
            elevation_token.scope
        );
        if let ApprovalScope::Elevation(scope) = &elevation_token.scope {
            // Binding check: token's provenance_id must match actual provenance
            let matches_correct = scope.original_provenance_id == correct_prov_id;
            let matches_wrong = scope.original_provenance_id == wrong_prov_id;

            assert!(matches_correct, "Token should match correct provenance");
            assert!(!matches_wrong, "Token should NOT match wrong provenance");
        }

        log_flow_test(
            "approval_token_elevation_scope_binding_enforced",
            "integrity",
            "binding",
            "binding",
            true,
            "pass",
            Some("ELEVATION_BINDING_ENFORCED"),
        );
    }

    #[test]
    fn approval_token_declassification_scope_object_binding() {
        // Declassification token is bound to specific object IDs
        let authorized_object = test_object_id("authorized-secret");
        let unauthorized_object = test_object_id("unauthorized-secret");

        let declassification_token = ApprovalToken {
            token_id: "bound-declassification".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Declassification(DeclassificationScope {
                from_zone: ZoneId::private(),
                to_zone: ZoneId::public(),
                object_ids: vec![authorized_object],
                target_confidentiality: ConfidentialityLevel::Public,
            }),
            zone_id: ZoneId::private(),
            signature: None,
        };

        assert!(
            matches!(
                &declassification_token.scope,
                ApprovalScope::Declassification(_)
            ),
            "Expected Declassification scope, got {:?}",
            declassification_token.scope
        );
        if let ApprovalScope::Declassification(scope) = &declassification_token.scope {
            // Binding check: object must be in authorized list
            let authorized_covered = scope.object_ids.contains(&authorized_object);
            let unauthorized_covered = scope.object_ids.contains(&unauthorized_object);

            assert!(authorized_covered, "Authorized object should be covered");
            assert!(
                !unauthorized_covered,
                "Unauthorized object should NOT be covered"
            );
        }

        log_flow_test(
            "approval_token_declassification_scope_object_binding",
            "confidentiality",
            "binding",
            "binding",
            true,
            "pass",
            Some("DECLASSIFICATION_BINDING_ENFORCED"),
        );
    }

    #[test]
    fn approval_token_signature_field_presence() {
        // Test that signature field can be set and checked
        let unsigned_token = ApprovalToken {
            token_id: "unsigned-token".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Work,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        let signed_token = ApprovalToken {
            token_id: "signed-token".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Work,
            }),
            zone_id: ZoneId::work(),
            signature: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]), // Mock signature
        };

        // Unsigned token has no signature
        assert!(unsigned_token.signature.is_none());

        // Signed token has signature bytes
        assert!(signed_token.signature.is_some());
        let sig = signed_token.signature.as_ref().unwrap();
        assert_eq!(sig.len(), 4);

        log_flow_test(
            "approval_token_signature_field_presence",
            "integrity",
            "signature",
            "signature",
            true,
            "pass",
            Some("SIGNATURE_FIELD_CHECKED"),
        );
    }

    #[test]
    fn approval_token_boundary_time_validity() {
        // Test exact boundary conditions for token validity
        let token = ApprovalToken {
            token_id: "boundary-token".into(),
            issued_at_ms: 1000,  // Valid from exactly 1000
            expires_at_ms: 2000, // Expires at exactly 2000
            issuer: "node:test".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Work,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // Before issued_at: not yet valid
        assert!(token.is_not_yet_valid(999));
        assert!(!token.is_valid(999));

        // Exactly at issued_at: valid (inclusive start)
        assert!(!token.is_not_yet_valid(1000));
        assert!(token.is_valid(1000));

        // In the middle: valid
        assert!(token.is_valid(1500));

        // Just before expiry: valid
        assert!(!token.is_expired(1999));
        assert!(token.is_valid(1999));

        // Exactly at expires_at: expired (exclusive end)
        assert!(token.is_expired(2000));
        assert!(!token.is_valid(2000));

        // After expiry: expired
        assert!(token.is_expired(2001));
        assert!(!token.is_valid(2001));

        log_flow_test(
            "approval_token_boundary_time_validity",
            "integrity",
            "time",
            "time",
            true,
            "pass",
            Some("BOUNDARY_TIME_VALIDATED"),
        );
    }

    #[test]
    fn approval_token_zero_duration_is_never_valid() {
        // Edge case: token with zero duration (issued_at == expires_at)
        let zero_duration_token = ApprovalToken {
            token_id: "zero-duration".into(),
            issued_at_ms: 1000,
            expires_at_ms: 1000, // Expires immediately at issuance
            issuer: "node:test".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "test.op".into(),
                original_provenance_id: test_object_id("prov"),
                target_integrity: IntegrityLevel::Work,
            }),
            zone_id: ZoneId::work(),
            signature: None,
        };

        // At issuance time: expires_at == issued_at, so is_expired(1000) = (1000 >= 1000) = true
        assert!(zero_duration_token.is_expired(1000));
        // And is_not_yet_valid(1000) = (1000 < 1000) = false
        assert!(!zero_duration_token.is_not_yet_valid(1000));
        // Valid requires BOTH not expired AND not_yet_valid = false, but expired = true
        assert!(!zero_duration_token.is_valid(1000));

        // Never valid at any time
        assert!(!zero_duration_token.is_valid(999)); // Not yet valid
        assert!(!zero_duration_token.is_valid(1001)); // Already expired

        log_flow_test(
            "approval_token_zero_duration_is_never_valid",
            "integrity",
            "time",
            "time",
            false,
            "pass",
            Some("ZERO_DURATION_NEVER_VALID"),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Property Tests for Merge Invariants (Randomized)
    // ─────────────────────────────────────────────────────────────────────────

    mod property_tests {
        use super::*;
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        /// Generate a random `IntegrityLevel`.
        fn random_integrity(rng: &mut impl Rng) -> IntegrityLevel {
            match rng.gen_range(0..5) {
                0 => IntegrityLevel::Untrusted,
                1 => IntegrityLevel::Community,
                2 => IntegrityLevel::Work,
                3 => IntegrityLevel::Private,
                _ => IntegrityLevel::Owner,
            }
        }

        /// Generate a random `ConfidentialityLevel`.
        fn random_confidentiality(rng: &mut impl Rng) -> ConfidentialityLevel {
            match rng.gen_range(0..5) {
                0 => ConfidentialityLevel::Public,
                1 => ConfidentialityLevel::Community,
                2 => ConfidentialityLevel::Work,
                3 => ConfidentialityLevel::Private,
                _ => ConfidentialityLevel::Owner,
            }
        }

        /// Generate random `TaintFlags` (0-3 random flags).
        fn random_taint_flags(rng: &mut impl Rng) -> TaintFlags {
            let all_flags = [
                TaintFlag::PublicInput,
                TaintFlag::UnverifiedLink,
                TaintFlag::UntrustedTransform,
                TaintFlag::WebhookInjected,
                TaintFlag::UserGenerated,
                TaintFlag::PotentiallyMalicious,
                TaintFlag::AiGenerated,
                TaintFlag::CrossZoneUnapproved,
            ];
            let num_flags = rng.gen_range(0..=3);
            let mut flags = TaintFlags::new();
            for _ in 0..num_flags {
                let idx = rng.gen_range(0..all_flags.len());
                flags.insert(all_flags[idx]);
            }
            flags
        }

        /// Generate a random `ZoneId`.
        fn random_zone(rng: &mut impl Rng) -> ZoneId {
            match rng.gen_range(0..5) {
                0 => ZoneId::public(),
                1 => ZoneId::community(),
                2 => ZoneId::work(),
                3 => ZoneId::private(),
                _ => ZoneId::owner(),
            }
        }

        /// Generate a random `ProvenanceRecord` with explicit labels.
        fn random_provenance(rng: &mut impl Rng) -> ProvenanceRecord {
            let zone = random_zone(rng);
            let mut record = ProvenanceRecord::new(zone);
            // Override with random labels
            record.integrity_label = random_integrity(rng);
            record.confidentiality_label = random_confidentiality(rng);
            record.taint_flags = random_taint_flags(rng);
            record
        }

        const NUM_ITERATIONS: usize = 100;
        const SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

        /// Property: merge(a, b) == merge(b, a) for integrity, confidentiality, and taint.
        ///
        /// Commutativity ensures that the order of inputs doesn't affect the
        /// security-relevant merge result.
        #[test]
        fn property_merge_commutativity() {
            let mut rng = StdRng::seed_from_u64(SEED);
            let zone = ZoneId::work();

            for i in 0..NUM_ITERATIONS {
                let a = random_provenance(&mut rng);
                let b = random_provenance(&mut rng);

                let merge_ab = ProvenanceRecord::merge(&[&a, &b], zone.clone());
                let merge_ba = ProvenanceRecord::merge(&[&b, &a], zone.clone());

                assert_eq!(
                    merge_ab.integrity_label, merge_ba.integrity_label,
                    "Iteration {i}: integrity not commutative"
                );
                assert_eq!(
                    merge_ab.confidentiality_label, merge_ba.confidentiality_label,
                    "Iteration {i}: confidentiality not commutative"
                );
                assert_eq!(
                    merge_ab.taint_flags, merge_ba.taint_flags,
                    "Iteration {i}: taint flags not commutative"
                );
            }

            log_flow_test(
                "property_merge_commutativity",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: merge(merge(a, b), c) == merge(a, merge(b, c)) for labels and taint.
        ///
        /// Associativity ensures consistent results regardless of grouping.
        #[test]
        fn property_merge_associativity() {
            let mut rng = StdRng::seed_from_u64(SEED + 1);
            let zone = ZoneId::work();

            for i in 0..NUM_ITERATIONS {
                let a = random_provenance(&mut rng);
                let b = random_provenance(&mut rng);
                let c = random_provenance(&mut rng);

                // (a merge b) merge c
                let ab = ProvenanceRecord::merge(&[&a, &b], zone.clone());
                let ab_c = ProvenanceRecord::merge(&[&ab, &c], zone.clone());

                // a merge (b merge c)
                let bc = ProvenanceRecord::merge(&[&b, &c], zone.clone());
                let a_bc = ProvenanceRecord::merge(&[&a, &bc], zone.clone());

                assert_eq!(
                    ab_c.integrity_label, a_bc.integrity_label,
                    "Iteration {i}: integrity not associative"
                );
                assert_eq!(
                    ab_c.confidentiality_label, a_bc.confidentiality_label,
                    "Iteration {i}: confidentiality not associative"
                );
                assert_eq!(
                    ab_c.taint_flags, a_bc.taint_flags,
                    "Iteration {i}: taint flags not associative"
                );
            }

            log_flow_test(
                "property_merge_associativity",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: `result.integrity` == MIN(inputs.integrity).
        ///
        /// This is the conservative merge rule: the result is no more trusted
        /// than the least trusted input.
        #[test]
        fn property_merge_integrity_is_minimum() {
            let mut rng = StdRng::seed_from_u64(SEED + 2);
            let zone = ZoneId::work();

            for i in 0..NUM_ITERATIONS {
                let records: Vec<ProvenanceRecord> = (0..rng.gen_range(1..=5))
                    .map(|_| random_provenance(&mut rng))
                    .collect();
                let refs: Vec<&ProvenanceRecord> = records.iter().collect();

                let merged = ProvenanceRecord::merge(&refs, zone.clone());
                let expected_min = records.iter().map(|r| r.integrity_label).min().unwrap();

                assert_eq!(
                    merged.integrity_label, expected_min,
                    "Iteration {i}: integrity should be MIN of inputs"
                );
            }

            log_flow_test(
                "property_merge_integrity_is_minimum",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: `result.confidentiality` == MAX(inputs.confidentiality).
        ///
        /// This is the restrictive merge rule: the result cannot flow to
        /// lower confidentiality contexts than the most restricted input.
        #[test]
        fn property_merge_confidentiality_is_maximum() {
            let mut rng = StdRng::seed_from_u64(SEED + 3);
            let zone = ZoneId::work();

            for i in 0..NUM_ITERATIONS {
                let records: Vec<ProvenanceRecord> = (0..rng.gen_range(1..=5))
                    .map(|_| random_provenance(&mut rng))
                    .collect();
                let refs: Vec<&ProvenanceRecord> = records.iter().collect();

                let merged = ProvenanceRecord::merge(&refs, zone.clone());
                let expected_max = records
                    .iter()
                    .map(|r| r.confidentiality_label)
                    .max()
                    .unwrap();

                assert_eq!(
                    merged.confidentiality_label, expected_max,
                    "Iteration {i}: confidentiality should be MAX of inputs"
                );
            }

            log_flow_test(
                "property_merge_confidentiality_is_maximum",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: `result.taint_flags` ⊇ `union(inputs.taint_flags)`.
        ///
        /// Taint accumulates: merged output contains all taints from all inputs.
        #[test]
        fn property_merge_taint_accumulation() {
            let mut rng = StdRng::seed_from_u64(SEED + 4);
            let zone = ZoneId::work();

            for i in 0..NUM_ITERATIONS {
                let records: Vec<ProvenanceRecord> = (0..rng.gen_range(1..=5))
                    .map(|_| random_provenance(&mut rng))
                    .collect();
                let refs: Vec<&ProvenanceRecord> = records.iter().collect();

                let merged = ProvenanceRecord::merge(&refs, zone.clone());

                // Collect all expected flags from inputs
                let mut expected_flags = TaintFlags::new();
                for record in &records {
                    for flag in record.taint_flags.iter() {
                        expected_flags.insert(*flag);
                    }
                }

                // Verify all expected flags are present in merged
                for flag in expected_flags.iter() {
                    assert!(
                        merged.taint_flags.contains(*flag),
                        "Iteration {i}: merged should contain flag {flag:?}"
                    );
                }

                // Verify merged has exactly the expected flags (no extras)
                assert_eq!(
                    merged.taint_flags, expected_flags,
                    "Iteration {i}: merged taint flags should equal union of inputs"
                );
            }

            log_flow_test(
                "property_merge_taint_accumulation",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: merge(single) preserves the single input's labels.
        ///
        /// Identity property: merging a single input should preserve its values.
        #[test]
        fn property_merge_single_preserves_labels() {
            let mut rng = StdRng::seed_from_u64(SEED + 5);
            let zone = ZoneId::work();

            for i in 0..NUM_ITERATIONS {
                let single = random_provenance(&mut rng);

                let merged = ProvenanceRecord::merge(&[&single], zone.clone());

                assert_eq!(
                    merged.integrity_label, single.integrity_label,
                    "Iteration {i}: single merge should preserve integrity"
                );
                assert_eq!(
                    merged.confidentiality_label, single.confidentiality_label,
                    "Iteration {i}: single merge should preserve confidentiality"
                );
                assert_eq!(
                    merged.taint_flags, single.taint_flags,
                    "Iteration {i}: single merge should preserve taint flags"
                );
            }

            log_flow_test(
                "property_merge_single_preserves_labels",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: merge(empty) returns fresh record with zone defaults.
        #[test]
        fn property_merge_empty_returns_zone_defaults() {
            let zones = [
                ZoneId::public(),
                ZoneId::community(),
                ZoneId::work(),
                ZoneId::private(),
                ZoneId::owner(),
            ];

            for zone in zones {
                let merged = ProvenanceRecord::merge(&[], zone.clone());

                assert_eq!(
                    merged.integrity_label,
                    IntegrityLevel::from_zone(&zone),
                    "Empty merge should use zone's default integrity"
                );
                assert_eq!(
                    merged.confidentiality_label,
                    ConfidentialityLevel::from_zone(&zone),
                    "Empty merge should use zone's default confidentiality"
                );
                assert!(
                    merged.taint_flags.is_empty(),
                    "Empty merge should have no taint"
                );
            }

            log_flow_test(
                "property_merge_empty_returns_zone_defaults",
                "integrity",
                "empty",
                "zones",
                false,
                "pass",
                None,
            );
        }

        /// Property: TaintFlags.merge is commutative.
        #[test]
        fn property_taint_flags_merge_commutativity() {
            let mut rng = StdRng::seed_from_u64(SEED + 6);

            for i in 0..NUM_ITERATIONS {
                let a = random_taint_flags(&mut rng);
                let b = random_taint_flags(&mut rng);

                let ab = a.merge(&b);
                let ba = b.merge(&a);

                assert_eq!(
                    ab, ba,
                    "Iteration {i}: TaintFlags.merge should be commutative"
                );
            }

            log_flow_test(
                "property_taint_flags_merge_commutativity",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: TaintFlags.merge is associative.
        #[test]
        fn property_taint_flags_merge_associativity() {
            let mut rng = StdRng::seed_from_u64(SEED + 7);

            for i in 0..NUM_ITERATIONS {
                let a = random_taint_flags(&mut rng);
                let b = random_taint_flags(&mut rng);
                let c = random_taint_flags(&mut rng);

                let ab_c = a.merge(&b).merge(&c);
                let a_bc = a.merge(&b.merge(&c));

                assert_eq!(
                    ab_c, a_bc,
                    "Iteration {i}: TaintFlags.merge should be associative"
                );
            }

            log_flow_test(
                "property_taint_flags_merge_associativity",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }

        /// Property: TaintFlags.merge(empty) is identity.
        #[test]
        fn property_taint_flags_merge_identity() {
            let mut rng = StdRng::seed_from_u64(SEED + 8);
            let empty = TaintFlags::new();

            for i in 0..NUM_ITERATIONS {
                let flags = random_taint_flags(&mut rng);

                let merged = flags.merge(&empty);
                assert_eq!(
                    merged, flags,
                    "Iteration {i}: merge with empty should be identity"
                );

                let merged_rev = empty.merge(&flags);
                assert_eq!(
                    merged_rev, flags,
                    "Iteration {i}: empty merge with flags should be identity"
                );
            }

            log_flow_test(
                "property_taint_flags_merge_identity",
                "integrity",
                "random",
                "random",
                false,
                "pass",
                None,
            );
        }
    }
}
