//! Release manifest and rollout policy types (NORMATIVE).
//!
//! This module provides Rust types matching the `ReleaseManifest_v1` and
//! `RolloutPolicy_v1` JSON schemas defined in `fcp-conformance`.
//!
//! # Release Manifest
//!
//! A release manifest describes a signed connector release with:
//! - Connector identity and version
//! - Content digest (blake3-256)
//! - Release channel (stable, canary, etc.)
//! - Required capabilities
//! - Minimum host version
//! - Ed25519 signature
//!
//! # Rollout Policy
//!
//! A rollout policy defines canary deployment behavior:
//! - Traffic percentage for canary
//! - Minimum canary duration
//! - Success thresholds for promotion
//! - Rollback rules for failure
//!
//! Note: Rates use basis points (bps, 0-10000) for precision.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ConnectorId;

// ─────────────────────────────────────────────────────────────────────────────
// Release Manifest
// ─────────────────────────────────────────────────────────────────────────────

/// Format identifier for release manifest JSON.
pub const RELEASE_MANIFEST_FORMAT: &str = "fcp-release-manifest";

/// Schema version for release manifest.
pub const RELEASE_MANIFEST_SCHEMA_VERSION: &str = "1.0";

/// Signed connector release manifest (NORMATIVE).
///
/// Matches the `ReleaseManifest_v1.schema.json` specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// Format identifier (always "fcp-release-manifest").
    pub format: String,

    /// Schema version (always "1.0" for v1).
    pub schema_version: String,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Semantic version of the release.
    pub version: String,

    /// Content digest in format `blake3-256:<hex>`.
    pub digest: String,

    /// Release channel (e.g., "stable", "canary", "beta").
    pub channel: String,

    /// Required capabilities for this connector.
    pub required_caps: Vec<String>,

    /// Minimum host version required.
    pub min_host_version: String,

    /// Entity that signed the release.
    pub signed_by: String,

    /// Release creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// Ed25519 signature.
    pub signature: ReleaseSignature,
}

impl ReleaseManifest {
    /// Create a new release manifest builder.
    #[must_use]
    pub fn builder(
        connector_id: ConnectorId,
        version: impl Into<String>,
    ) -> ReleaseManifestBuilder {
        ReleaseManifestBuilder::new(connector_id, version)
    }

    /// Validate the manifest structure.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::InvalidManifest`] if validation fails.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.format != RELEASE_MANIFEST_FORMAT {
            return Err(ReleaseError::InvalidManifest {
                reason: format!(
                    "format must be '{}', got '{}'",
                    RELEASE_MANIFEST_FORMAT, self.format
                ),
            });
        }
        if self.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidManifest {
                reason: format!(
                    "schema_version must be '{}', got '{}'",
                    RELEASE_MANIFEST_SCHEMA_VERSION, self.schema_version
                ),
            });
        }
        if self.version.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "version cannot be empty".to_string(),
            });
        }
        if !self.digest.starts_with("blake3-256:") || self.digest.len() != 75 {
            return Err(ReleaseError::InvalidManifest {
                reason: "digest must be in format 'blake3-256:<64-hex-chars>'".to_string(),
            });
        }
        if self.channel.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "channel cannot be empty".to_string(),
            });
        }
        if self.min_host_version.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "min_host_version cannot be empty".to_string(),
            });
        }
        if self.signed_by.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "signed_by cannot be empty".to_string(),
            });
        }
        self.signature.validate()?;
        Ok(())
    }

    /// Get the hex portion of the digest.
    #[must_use]
    pub fn digest_hex(&self) -> Option<&str> {
        self.digest.strip_prefix("blake3-256:")
    }
}

/// Builder for [`ReleaseManifest`].
#[derive(Debug, Clone)]
pub struct ReleaseManifestBuilder {
    connector_id: ConnectorId,
    version: String,
    digest: String,
    channel: String,
    required_caps: Vec<String>,
    min_host_version: String,
    signed_by: String,
    created_at: Option<DateTime<Utc>>,
    signature: Option<ReleaseSignature>,
}

impl ReleaseManifestBuilder {
    /// Create a new builder.
    fn new(connector_id: ConnectorId, version: impl Into<String>) -> Self {
        Self {
            connector_id,
            version: version.into(),
            digest: String::new(),
            channel: "stable".to_string(),
            required_caps: Vec::new(),
            min_host_version: String::new(),
            signed_by: String::new(),
            created_at: None,
            signature: None,
        }
    }

    /// Set the content digest.
    #[must_use]
    pub fn digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = digest.into();
        self
    }

    /// Set the release channel.
    #[must_use]
    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = channel.into();
        self
    }

    /// Set the required capabilities.
    #[must_use]
    pub fn required_caps(mut self, caps: Vec<String>) -> Self {
        self.required_caps = caps;
        self
    }

    /// Add a required capability.
    #[must_use]
    pub fn add_required_cap(mut self, cap: impl Into<String>) -> Self {
        self.required_caps.push(cap.into());
        self
    }

    /// Set the minimum host version.
    #[must_use]
    pub fn min_host_version(mut self, version: impl Into<String>) -> Self {
        self.min_host_version = version.into();
        self
    }

    /// Set who signed the release.
    #[must_use]
    pub fn signed_by(mut self, signer: impl Into<String>) -> Self {
        self.signed_by = signer.into();
        self
    }

    /// Set the creation timestamp.
    #[must_use]
    pub const fn created_at(mut self, timestamp: DateTime<Utc>) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Set the signature.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // ReleaseSignature has String fields with destructors
    pub fn signature(mut self, signature: ReleaseSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Build the release manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::InvalidManifest`] if required fields are missing.
    pub fn build(self) -> Result<ReleaseManifest, ReleaseError> {
        let signature = self
            .signature
            .ok_or_else(|| ReleaseError::InvalidManifest {
                reason: "signature is required".to_string(),
            })?;

        let manifest = ReleaseManifest {
            format: RELEASE_MANIFEST_FORMAT.to_string(),
            schema_version: RELEASE_MANIFEST_SCHEMA_VERSION.to_string(),
            connector_id: self.connector_id,
            version: self.version,
            digest: self.digest,
            channel: self.channel,
            required_caps: self.required_caps,
            min_host_version: self.min_host_version,
            signed_by: self.signed_by,
            created_at: self.created_at,
            signature,
        };

        manifest.validate()?;
        Ok(manifest)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Release Signature
// ─────────────────────────────────────────────────────────────────────────────

/// Ed25519 signature for a release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSignature {
    /// Signature algorithm (always "ed25519").
    pub algorithm: String,

    /// Key identifier used for signing.
    pub key_id: String,

    /// Base64 or hex encoded signature.
    pub signature: String,

    /// Fields that were signed.
    pub signed_fields: Vec<String>,
}

impl ReleaseSignature {
    /// Create a new Ed25519 signature.
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        signature: impl Into<String>,
        signed_fields: Vec<String>,
    ) -> Self {
        Self {
            algorithm: "ed25519".to_string(),
            key_id: key_id.into(),
            signature: signature.into(),
            signed_fields,
        }
    }

    /// Validate the signature structure.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::InvalidManifest`] if validation fails.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.algorithm != "ed25519" {
            return Err(ReleaseError::InvalidManifest {
                reason: format!("algorithm must be 'ed25519', got '{}'", self.algorithm),
            });
        }
        if self.key_id.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "key_id cannot be empty".to_string(),
            });
        }
        if self.signature.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "signature cannot be empty".to_string(),
            });
        }
        if self.signed_fields.is_empty() {
            return Err(ReleaseError::InvalidManifest {
                reason: "signed_fields cannot be empty".to_string(),
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rollout Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Format identifier for rollout policy JSON.
pub const ROLLOUT_POLICY_FORMAT: &str = "fcp-rollout-policy";

/// Schema version for rollout policy.
pub const ROLLOUT_POLICY_SCHEMA_VERSION: &str = "1.0";

/// Maximum value for basis points (100%).
pub const MAX_BPS: u16 = 10_000;

/// Rollout policy for canary deployments (NORMATIVE).
///
/// Matches the `RolloutPolicy_v1.schema.json` specification.
///
/// Note: Rates are specified in basis points (bps, 0-10000) where
/// 10000 bps = 100%. This provides 0.01% precision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPolicy {
    /// Format identifier (always "fcp-rollout-policy").
    pub format: String,

    /// Schema version (always "1.0" for v1).
    pub schema_version: String,

    /// Percentage of traffic to route to canary (0-100).
    pub canary_percent: u8,

    /// Minimum canary duration in seconds.
    pub min_canary_duration_secs: u32,

    /// Success thresholds for promotion.
    pub success_thresholds: SuccessThresholds,

    /// Rollback rules for failure.
    pub rollback_rules: RollbackRules,

    /// Policy creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

impl RolloutPolicy {
    /// Create a new rollout policy with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for customizing the policy.
    #[must_use]
    pub fn builder() -> RolloutPolicyBuilder {
        RolloutPolicyBuilder::default()
    }

    /// Validate the policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::InvalidPolicy`] if validation fails.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.format != ROLLOUT_POLICY_FORMAT {
            return Err(ReleaseError::InvalidPolicy {
                reason: format!(
                    "format must be '{}', got '{}'",
                    ROLLOUT_POLICY_FORMAT, self.format
                ),
            });
        }
        if self.schema_version != ROLLOUT_POLICY_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidPolicy {
                reason: format!(
                    "schema_version must be '{}', got '{}'",
                    ROLLOUT_POLICY_SCHEMA_VERSION, self.schema_version
                ),
            });
        }
        if self.canary_percent > 100 {
            return Err(ReleaseError::InvalidPolicy {
                reason: "canary_percent must be 0-100".to_string(),
            });
        }
        self.success_thresholds.validate()?;
        self.rollback_rules.validate()?;

        // Promotion error tolerance should be stricter than rollback threshold.
        // E.g., if promotion allows max 5% error, rollback should trigger at >= 5%.
        if self.success_thresholds.max_error_rate_bps > self.rollback_rules.max_error_rate_bps {
            return Err(ReleaseError::InvalidPolicy {
                reason: "promotion error tolerance cannot exceed rollback threshold".to_string(),
            });
        }

        Ok(())
    }

    /// Convert success rate from basis points to percentage.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn success_rate_percent(&self) -> f64 {
        f64::from(self.success_thresholds.min_success_rate_bps) / 100.0
    }

    /// Convert error rate from basis points to percentage.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn error_rate_percent(&self) -> f64 {
        f64::from(self.rollback_rules.max_error_rate_bps) / 100.0
    }
}

impl Default for RolloutPolicy {
    fn default() -> Self {
        Self {
            format: ROLLOUT_POLICY_FORMAT.to_string(),
            schema_version: ROLLOUT_POLICY_SCHEMA_VERSION.to_string(),
            canary_percent: 10,
            min_canary_duration_secs: 300,
            success_thresholds: SuccessThresholds::default(),
            rollback_rules: RollbackRules::default(),
            created_at: None,
        }
    }
}

/// Builder for [`RolloutPolicy`].
#[derive(Debug, Clone, Default)]
pub struct RolloutPolicyBuilder {
    canary_percent: Option<u8>,
    min_canary_duration_secs: Option<u32>,
    success_thresholds: Option<SuccessThresholds>,
    rollback_rules: Option<RollbackRules>,
    created_at: Option<DateTime<Utc>>,
}

impl RolloutPolicyBuilder {
    /// Set the canary traffic percentage.
    #[must_use]
    pub const fn canary_percent(mut self, percent: u8) -> Self {
        self.canary_percent = Some(percent);
        self
    }

    /// Set the minimum canary duration.
    #[must_use]
    pub const fn min_canary_duration_secs(mut self, secs: u32) -> Self {
        self.min_canary_duration_secs = Some(secs);
        self
    }

    /// Set the success thresholds.
    #[must_use]
    pub const fn success_thresholds(mut self, thresholds: SuccessThresholds) -> Self {
        self.success_thresholds = Some(thresholds);
        self
    }

    /// Set the rollback rules.
    #[must_use]
    pub const fn rollback_rules(mut self, rules: RollbackRules) -> Self {
        self.rollback_rules = Some(rules);
        self
    }

    /// Set the creation timestamp.
    #[must_use]
    pub const fn created_at(mut self, timestamp: DateTime<Utc>) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Build the rollout policy.
    #[must_use]
    pub fn build(self) -> RolloutPolicy {
        RolloutPolicy {
            format: ROLLOUT_POLICY_FORMAT.to_string(),
            schema_version: ROLLOUT_POLICY_SCHEMA_VERSION.to_string(),
            canary_percent: self.canary_percent.unwrap_or(10),
            min_canary_duration_secs: self.min_canary_duration_secs.unwrap_or(300),
            success_thresholds: self.success_thresholds.unwrap_or_default(),
            rollback_rules: self.rollback_rules.unwrap_or_default(),
            created_at: self.created_at,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Success Thresholds
// ─────────────────────────────────────────────────────────────────────────────

/// Success thresholds for canary promotion.
///
/// All rates are in basis points (bps, 0-10000).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessThresholds {
    /// Minimum success rate in basis points (e.g., 9500 = 95%).
    pub min_success_rate_bps: u16,

    /// Maximum error rate in basis points (e.g., 500 = 5%).
    pub max_error_rate_bps: u16,

    /// Minimum number of samples before evaluation.
    pub min_samples: u32,

    /// Evaluation window in seconds.
    pub window_secs: u32,
}

impl SuccessThresholds {
    /// Create new success thresholds.
    #[must_use]
    pub const fn new(
        min_success_rate_bps: u16,
        max_error_rate_bps: u16,
        min_samples: u32,
        window_secs: u32,
    ) -> Self {
        Self {
            min_success_rate_bps,
            max_error_rate_bps,
            min_samples,
            window_secs,
        }
    }

    /// Validate the thresholds.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::InvalidPolicy`] if validation fails.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.min_success_rate_bps > MAX_BPS {
            return Err(ReleaseError::InvalidPolicy {
                reason: format!(
                    "min_success_rate_bps must be 0-{}, got {}",
                    MAX_BPS, self.min_success_rate_bps
                ),
            });
        }
        if self.max_error_rate_bps > MAX_BPS {
            return Err(ReleaseError::InvalidPolicy {
                reason: format!(
                    "max_error_rate_bps must be 0-{}, got {}",
                    MAX_BPS, self.max_error_rate_bps
                ),
            });
        }
        Ok(())
    }

    /// Convert success rate to percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn success_rate_percent(&self) -> f64 {
        f64::from(self.min_success_rate_bps) / 100.0
    }

    /// Convert error rate to percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn error_rate_percent(&self) -> f64 {
        f64::from(self.max_error_rate_bps) / 100.0
    }
}

impl Default for SuccessThresholds {
    fn default() -> Self {
        Self {
            min_success_rate_bps: 9500, // 95%
            max_error_rate_bps: 500,    // 5%
            min_samples: 100,
            window_secs: 300, // 5 minutes
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rollback Rules
// ─────────────────────────────────────────────────────────────────────────────

/// Rollback rules for canary failure.
///
/// Rates are in basis points (bps, 0-10000).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRules {
    /// Maximum error rate before rollback (in basis points).
    pub max_error_rate_bps: u16,

    /// Maximum consecutive failures before rollback.
    pub max_consecutive_failures: u32,

    /// Minimum samples before evaluation.
    pub min_samples: u32,

    /// Evaluation window in seconds.
    pub window_secs: u32,

    /// Whether to automatically rollback on threshold breach.
    pub auto_rollback: bool,
}

impl RollbackRules {
    /// Create new rollback rules.
    #[must_use]
    pub const fn new(
        max_error_rate_bps: u16,
        max_consecutive_failures: u32,
        min_samples: u32,
        window_secs: u32,
        auto_rollback: bool,
    ) -> Self {
        Self {
            max_error_rate_bps,
            max_consecutive_failures,
            min_samples,
            window_secs,
            auto_rollback,
        }
    }

    /// Validate the rules.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::InvalidPolicy`] if validation fails.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.max_error_rate_bps > MAX_BPS {
            return Err(ReleaseError::InvalidPolicy {
                reason: format!(
                    "max_error_rate_bps must be 0-{}, got {}",
                    MAX_BPS, self.max_error_rate_bps
                ),
            });
        }
        if self.max_consecutive_failures == 0 {
            return Err(ReleaseError::InvalidPolicy {
                reason: "max_consecutive_failures must be at least 1".to_string(),
            });
        }
        Ok(())
    }

    /// Convert error rate to percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn error_rate_percent(&self) -> f64 {
        f64::from(self.max_error_rate_bps) / 100.0
    }
}

impl Default for RollbackRules {
    fn default() -> Self {
        Self {
            max_error_rate_bps: 2000, // 20%
            max_consecutive_failures: 5,
            min_samples: 10,
            window_secs: 60, // 1 minute
            auto_rollback: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Release Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during release operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// Invalid release manifest.
    InvalidManifest {
        /// Reason for invalidity.
        reason: String,
    },

    /// Invalid rollout policy.
    InvalidPolicy {
        /// Reason for invalidity.
        reason: String,
    },

    /// Signature verification failed.
    SignatureVerificationFailed {
        /// Details about the failure.
        reason: String,
    },

    /// Release not found.
    NotFound {
        /// Connector ID.
        connector_id: ConnectorId,
        /// Version that was not found.
        version: String,
    },
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest { reason } => {
                write!(f, "invalid release manifest: {reason}")
            }
            Self::InvalidPolicy { reason } => {
                write!(f, "invalid rollout policy: {reason}")
            }
            Self::SignatureVerificationFailed { reason } => {
                write!(f, "signature verification failed: {reason}")
            }
            Self::NotFound {
                connector_id,
                version,
            } => {
                write!(f, "release not found: {connector_id}@{version}")
            }
        }
    }
}

impl std::error::Error for ReleaseError {}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("test:release:v1")
    }

    fn test_digest() -> String {
        format!("blake3-256:{}", "a".repeat(64))
    }

    fn test_signature() -> ReleaseSignature {
        ReleaseSignature::new(
            "key-001",
            "sig-data",
            vec![
                "connector_id".to_string(),
                "version".to_string(),
                "digest".to_string(),
            ],
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseManifest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_manifest_builder() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .channel("stable")
            .min_host_version("0.1.0")
            .signed_by("publisher@example.com")
            .add_required_cap("net:http")
            .signature(test_signature())
            .build()
            .unwrap();

        assert_eq!(manifest.format, RELEASE_MANIFEST_FORMAT);
        assert_eq!(manifest.schema_version, RELEASE_MANIFEST_SCHEMA_VERSION);
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.channel, "stable");
        assert_eq!(manifest.required_caps, vec!["net:http"]);
    }

    #[test]
    fn release_manifest_validation_format() {
        let mut manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();

        manifest.format = "wrong".to_string();
        assert!(matches!(
            manifest.validate(),
            Err(ReleaseError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn release_manifest_validation_digest() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest("invalid-digest")
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();

        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn release_manifest_digest_hex() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();

        assert_eq!(manifest.digest_hex(), Some("a".repeat(64).as_str()));
    }

    #[test]
    fn release_manifest_serde_roundtrip() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .channel("canary")
            .min_host_version("0.1.0")
            .signed_by("test")
            .add_required_cap("net:http")
            .signature(test_signature())
            .build()
            .unwrap();

        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: ReleaseManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseSignature Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_signature_new() {
        let sig = ReleaseSignature::new("key-001", "signature", vec!["field1".to_string()]);
        assert_eq!(sig.algorithm, "ed25519");
        assert_eq!(sig.key_id, "key-001");
    }

    #[test]
    fn release_signature_validation() {
        let mut sig = test_signature();
        sig.algorithm = "rsa".to_string();
        assert!(matches!(
            sig.validate(),
            Err(ReleaseError::InvalidManifest { .. })
        ));

        let mut sig = test_signature();
        sig.key_id = String::new();
        assert!(matches!(
            sig.validate(),
            Err(ReleaseError::InvalidManifest { .. })
        ));

        let mut sig = test_signature();
        sig.signed_fields = vec![];
        assert!(matches!(
            sig.validate(),
            Err(ReleaseError::InvalidManifest { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RolloutPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollout_policy_default() {
        let policy = RolloutPolicy::default();
        assert_eq!(policy.format, ROLLOUT_POLICY_FORMAT);
        assert_eq!(policy.schema_version, ROLLOUT_POLICY_SCHEMA_VERSION);
        assert_eq!(policy.canary_percent, 10);
        assert_eq!(policy.min_canary_duration_secs, 300);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rollout_policy_builder() {
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(600)
            .success_thresholds(SuccessThresholds::new(9900, 100, 50, 120))
            .rollback_rules(RollbackRules::new(1000, 3, 5, 30, true))
            .build();

        assert_eq!(policy.canary_percent, 5);
        assert_eq!(policy.min_canary_duration_secs, 600);
        assert_eq!(policy.success_thresholds.min_success_rate_bps, 9900);
        assert_eq!(policy.rollback_rules.max_error_rate_bps, 1000);
    }

    #[test]
    fn rollout_policy_validation_format() {
        let policy = RolloutPolicy {
            format: "wrong".to_string(),
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollout_policy_validation_canary_percent() {
        let policy = RolloutPolicy {
            canary_percent: 150,
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollout_policy_rate_conversions() {
        let policy = RolloutPolicy::default();
        assert!((policy.success_rate_percent() - 95.0).abs() < f64::EPSILON);
        assert!((policy.error_rate_percent() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rollout_policy_validation_threshold_consistency() {
        // Promotion error tolerance cannot exceed rollback threshold.
        // If promotion allows 20% error but rollback triggers at 5%, that's invalid.
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(8000, 2000, 50, 120)) // 20% max error for promotion
            .rollback_rules(RollbackRules::new(500, 3, 5, 30, true)) // 5% triggers rollback
            .build();

        assert!(matches!(
            policy.validate(),
            Err(ReleaseError::InvalidPolicy { reason }) if reason.contains("promotion error tolerance")
        ));
    }

    #[test]
    fn rollout_policy_serde_roundtrip() {
        let policy = RolloutPolicy::builder()
            .canary_percent(15)
            .min_canary_duration_secs(120)
            .build();

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: RolloutPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SuccessThresholds Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn success_thresholds_default() {
        let thresholds = SuccessThresholds::default();
        assert_eq!(thresholds.min_success_rate_bps, 9500);
        assert_eq!(thresholds.max_error_rate_bps, 500);
        assert_eq!(thresholds.min_samples, 100);
        assert_eq!(thresholds.window_secs, 300);
    }

    #[test]
    fn success_thresholds_validation() {
        let thresholds = SuccessThresholds {
            min_success_rate_bps: 15000,
            ..Default::default()
        };
        assert!(matches!(
            thresholds.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn success_thresholds_rate_conversions() {
        let thresholds = SuccessThresholds::new(9750, 250, 50, 60);
        assert!((thresholds.success_rate_percent() - 97.5).abs() < f64::EPSILON);
        assert!((thresholds.error_rate_percent() - 2.5).abs() < f64::EPSILON);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RollbackRules Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollback_rules_default() {
        let rules = RollbackRules::default();
        assert_eq!(rules.max_error_rate_bps, 2000);
        assert_eq!(rules.max_consecutive_failures, 5);
        assert_eq!(rules.min_samples, 10);
        assert_eq!(rules.window_secs, 60);
        assert!(rules.auto_rollback);
    }

    #[test]
    fn rollback_rules_validation_error_rate() {
        let rules = RollbackRules {
            max_error_rate_bps: 15000,
            ..Default::default()
        };
        assert!(matches!(
            rules.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollback_rules_validation_consecutive_failures() {
        let rules = RollbackRules {
            max_consecutive_failures: 0,
            ..Default::default()
        };
        assert!(matches!(
            rules.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollback_rules_rate_conversion() {
        let rules = RollbackRules::new(1500, 3, 10, 60, true);
        assert!((rules.error_rate_percent() - 15.0).abs() < f64::EPSILON);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseError Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_error_display() {
        let err = ReleaseError::InvalidManifest {
            reason: "bad format".to_string(),
        };
        assert!(err.to_string().contains("bad format"));

        let err = ReleaseError::InvalidPolicy {
            reason: "bad threshold".to_string(),
        };
        assert!(err.to_string().contains("bad threshold"));

        let err = ReleaseError::SignatureVerificationFailed {
            reason: "invalid sig".to_string(),
        };
        assert!(err.to_string().contains("invalid sig"));

        let err = ReleaseError::NotFound {
            connector_id: test_connector_id(),
            version: "1.0.0".to_string(),
        };
        assert!(err.to_string().contains("1.0.0"));
    }

    #[test]
    fn release_manifest_missing_signature() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .build();

        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn release_manifest_empty_fields() {
        // Empty version
        let result = ReleaseManifest::builder(test_connector_id(), "")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));

        // Empty channel
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .channel("")
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));

        // Empty min_host_version
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));

        // Empty signed_by
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }
}
