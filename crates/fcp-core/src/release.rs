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

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ReleaseManifest tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_manifest_validation_schema_version() {
        let mut manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();

        manifest.schema_version = "2.0".to_string();
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn release_manifest_digest_wrong_prefix() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(format!("sha256:{}", "a".repeat(64)))
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn release_manifest_digest_too_short() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(format!("blake3-256:{}", "a".repeat(32)))
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn release_manifest_digest_too_long() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(format!("blake3-256:{}", "a".repeat(128)))
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn release_manifest_digest_empty() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest("")
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn release_manifest_digest_hex_no_prefix() {
        let mut manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();

        manifest.digest = "no-prefix-here".to_string();
        assert!(manifest.digest_hex().is_none());
    }

    #[test]
    fn release_manifest_builder_default_channel() {
        // Builder defaults to "stable" channel
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.channel, "stable");
    }

    #[test]
    fn release_manifest_builder_required_caps_batch() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .required_caps(vec![
                "net:http".to_string(),
                "fs:read".to_string(),
                "secret:read".to_string(),
            ])
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.required_caps.len(), 3);
        assert_eq!(manifest.required_caps[2], "secret:read");
    }

    #[test]
    fn release_manifest_builder_add_required_cap_chaining() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .add_required_cap("net:http")
            .add_required_cap("fs:write")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.required_caps, vec!["net:http", "fs:write"]);
    }

    #[test]
    fn release_manifest_builder_created_at() {
        let ts = chrono::Utc::now();
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .created_at(ts)
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.created_at, Some(ts));
    }

    #[test]
    fn release_manifest_created_at_none_by_default() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        assert!(manifest.created_at.is_none());
    }

    #[test]
    fn release_manifest_created_at_omitted_in_json() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        let value = serde_json::to_value(&manifest).unwrap();
        assert!(value.get("created_at").is_none());
    }

    #[test]
    fn release_manifest_created_at_present_in_json() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .created_at(chrono::Utc::now())
            .signature(test_signature())
            .build()
            .unwrap();
        let value = serde_json::to_value(&manifest).unwrap();
        assert!(value.get("created_at").is_some());
    }

    #[test]
    fn release_manifest_serde_roundtrip_with_caps_and_timestamp() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "2.5.0")
            .digest(test_digest())
            .channel("beta")
            .min_host_version("1.0.0")
            .signed_by("publisher@example.com")
            .required_caps(vec!["net:http".to_string(), "gpu:infer".to_string()])
            .created_at(chrono::Utc::now())
            .signature(test_signature())
            .build()
            .unwrap();

        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: ReleaseManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn release_manifest_clone() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        let cloned = manifest.clone();
        assert_eq!(manifest, cloned);
    }

    #[test]
    fn release_manifest_format_constant() {
        assert_eq!(RELEASE_MANIFEST_FORMAT, "fcp-release-manifest");
        assert_eq!(RELEASE_MANIFEST_SCHEMA_VERSION, "1.0");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ReleaseSignature tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_signature_validates_ok() {
        let sig = test_signature();
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn release_signature_empty_signature_data() {
        let sig = ReleaseSignature::new("key-001", "", vec!["field1".to_string()]);
        let err = sig.validate().unwrap_err();
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn release_signature_serde_roundtrip() {
        let sig = test_signature();
        let json = serde_json::to_string(&sig).unwrap();
        let decoded: ReleaseSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn release_signature_algorithm_always_ed25519() {
        let sig = ReleaseSignature::new("k", "s", vec!["f".to_string()]);
        assert_eq!(sig.algorithm, "ed25519");
    }

    #[test]
    fn release_signature_clone() {
        let sig = test_signature();
        let cloned = sig.clone();
        assert_eq!(sig, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional RolloutPolicy tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollout_policy_new_equals_default() {
        let a = RolloutPolicy::new();
        let b = RolloutPolicy::default();
        assert_eq!(a, b);
    }

    #[test]
    fn rollout_policy_validation_schema_version() {
        let policy = RolloutPolicy {
            schema_version: "2.0".to_string(),
            ..Default::default()
        };
        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn rollout_policy_canary_percent_boundary_0() {
        let policy = RolloutPolicy {
            canary_percent: 0,
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rollout_policy_canary_percent_boundary_100() {
        let policy = RolloutPolicy {
            canary_percent: 100,
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rollout_policy_canary_percent_boundary_101() {
        let policy = RolloutPolicy {
            canary_percent: 101,
            ..Default::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn rollout_policy_builder_defaults() {
        let policy = RolloutPolicy::builder().build();
        assert_eq!(policy.canary_percent, 10);
        assert_eq!(policy.min_canary_duration_secs, 300);
    }

    #[test]
    fn rollout_policy_builder_created_at() {
        let ts = chrono::Utc::now();
        let policy = RolloutPolicy::builder().created_at(ts).build();
        assert_eq!(policy.created_at, Some(ts));
    }

    #[test]
    fn rollout_policy_created_at_none_by_default() {
        let policy = RolloutPolicy::default();
        assert!(policy.created_at.is_none());
    }

    #[test]
    fn rollout_policy_created_at_omitted_in_json() {
        let policy = RolloutPolicy::default();
        let value = serde_json::to_value(&policy).unwrap();
        assert!(value.get("created_at").is_none());
    }

    #[test]
    fn rollout_policy_threshold_consistency_equal_ok() {
        // Equal promotion error and rollback error is valid
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9500, 500, 50, 120))
            .rollback_rules(RollbackRules::new(500, 3, 5, 30, true))
            .build();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rollout_policy_threshold_consistency_promotion_lower_ok() {
        // Promotion error tolerance < rollback threshold is valid
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9700, 300, 50, 120))
            .rollback_rules(RollbackRules::new(500, 3, 5, 30, true))
            .build();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rollout_policy_format_constant() {
        assert_eq!(ROLLOUT_POLICY_FORMAT, "fcp-rollout-policy");
        assert_eq!(ROLLOUT_POLICY_SCHEMA_VERSION, "1.0");
    }

    #[test]
    fn max_bps_constant() {
        assert_eq!(MAX_BPS, 10_000);
    }

    #[test]
    fn rollout_policy_clone() {
        let policy = RolloutPolicy::default();
        let cloned = policy.clone();
        assert_eq!(policy, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional SuccessThresholds tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn success_thresholds_max_bps_boundary() {
        let thresholds = SuccessThresholds::new(MAX_BPS, MAX_BPS, 1, 1);
        assert!(thresholds.validate().is_ok());
    }

    #[test]
    fn success_thresholds_max_bps_plus_one() {
        let thresholds = SuccessThresholds::new(MAX_BPS + 1, 500, 100, 300);
        assert!(thresholds.validate().is_err());
    }

    #[test]
    fn success_thresholds_error_rate_overflow() {
        let thresholds = SuccessThresholds {
            max_error_rate_bps: MAX_BPS + 1,
            ..Default::default()
        };
        assert!(thresholds.validate().is_err());
    }

    #[test]
    fn success_thresholds_zero_bps() {
        let thresholds = SuccessThresholds::new(0, 0, 1, 1);
        assert!(thresholds.validate().is_ok());
    }

    #[test]
    fn success_thresholds_rate_percent_zero() {
        let thresholds = SuccessThresholds::new(0, 0, 1, 1);
        assert!((thresholds.success_rate_percent()).abs() < f64::EPSILON);
        assert!((thresholds.error_rate_percent()).abs() < f64::EPSILON);
    }

    #[test]
    fn success_thresholds_rate_percent_100() {
        let thresholds = SuccessThresholds::new(MAX_BPS, MAX_BPS, 1, 1);
        assert!((thresholds.success_rate_percent() - 100.0).abs() < f64::EPSILON);
        assert!((thresholds.error_rate_percent() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn success_thresholds_serde_roundtrip() {
        let thresholds = SuccessThresholds::new(9800, 200, 50, 120);
        let json = serde_json::to_string(&thresholds).unwrap();
        let decoded: SuccessThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(thresholds, decoded);
    }

    #[test]
    fn success_thresholds_clone() {
        let a = SuccessThresholds::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional RollbackRules tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollback_rules_max_bps_boundary() {
        let rules = RollbackRules::new(MAX_BPS, 1, 1, 1, true);
        assert!(rules.validate().is_ok());
    }

    #[test]
    fn rollback_rules_max_bps_plus_one() {
        let rules = RollbackRules::new(MAX_BPS + 1, 1, 1, 1, true);
        assert!(rules.validate().is_err());
    }

    #[test]
    fn rollback_rules_consecutive_failures_one_ok() {
        let rules = RollbackRules::new(2000, 1, 10, 60, true);
        assert!(rules.validate().is_ok());
    }

    #[test]
    fn rollback_rules_auto_rollback_false() {
        let rules = RollbackRules::new(2000, 5, 10, 60, false);
        assert!(!rules.auto_rollback);
        assert!(rules.validate().is_ok());
    }

    #[test]
    fn rollback_rules_error_rate_percent_zero() {
        let rules = RollbackRules::new(0, 1, 1, 1, true);
        assert!((rules.error_rate_percent()).abs() < f64::EPSILON);
    }

    #[test]
    fn rollback_rules_error_rate_percent_100() {
        let rules = RollbackRules::new(MAX_BPS, 1, 1, 1, true);
        assert!((rules.error_rate_percent() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rollback_rules_serde_roundtrip() {
        let rules = RollbackRules::new(1500, 3, 10, 60, true);
        let json = serde_json::to_string(&rules).unwrap();
        let decoded: RollbackRules = serde_json::from_str(&json).unwrap();
        assert_eq!(rules, decoded);
    }

    #[test]
    fn rollback_rules_clone() {
        let a = RollbackRules::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ReleaseError tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_error_invalid_manifest_display_prefix() {
        let err = ReleaseError::InvalidManifest {
            reason: "test".to_string(),
        };
        assert!(err.to_string().starts_with("invalid release manifest:"));
    }

    #[test]
    fn release_error_invalid_policy_display_prefix() {
        let err = ReleaseError::InvalidPolicy {
            reason: "test".to_string(),
        };
        assert!(err.to_string().starts_with("invalid rollout policy:"));
    }

    #[test]
    fn release_error_signature_failed_display_prefix() {
        let err = ReleaseError::SignatureVerificationFailed {
            reason: "test".to_string(),
        };
        assert!(
            err.to_string()
                .starts_with("signature verification failed:")
        );
    }

    #[test]
    fn release_error_not_found_display() {
        let err = ReleaseError::NotFound {
            connector_id: test_connector_id(),
            version: "3.0.0".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("test:release:v1"));
        assert!(s.contains("3.0.0"));
    }

    #[test]
    fn release_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ReleaseError::InvalidManifest {
            reason: "test".to_string(),
        });
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn release_error_equality() {
        let a = ReleaseError::InvalidManifest {
            reason: "same".to_string(),
        };
        let b = ReleaseError::InvalidManifest {
            reason: "same".to_string(),
        };
        let c = ReleaseError::InvalidManifest {
            reason: "different".to_string(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn release_error_clone() {
        let err = ReleaseError::InvalidPolicy {
            reason: "test".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Builder edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn builder_required_caps_override() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .add_required_cap("cap1")
            .required_caps(vec!["cap2".to_string(), "cap3".to_string()])
            .signature(test_signature())
            .build()
            .unwrap();
        // required_caps() replaces the list, so cap1 is gone
        assert_eq!(manifest.required_caps, vec!["cap2", "cap3"]);
    }

    #[test]
    fn builder_channel_override() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .channel("canary")
            .channel("beta")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.channel, "beta");
    }

    #[test]
    fn builder_empty_required_caps_valid() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        assert!(manifest.required_caps.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RolloutPolicyBuilder edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollout_policy_builder_all_fields() {
        let ts = chrono::Utc::now();
        let policy = RolloutPolicy::builder()
            .canary_percent(25)
            .min_canary_duration_secs(900)
            .success_thresholds(SuccessThresholds::new(9800, 200, 200, 600))
            .rollback_rules(RollbackRules::new(500, 10, 50, 120, false))
            .created_at(ts)
            .build();

        assert_eq!(policy.canary_percent, 25);
        assert_eq!(policy.min_canary_duration_secs, 900);
        assert_eq!(policy.success_thresholds.min_success_rate_bps, 9800);
        assert_eq!(policy.rollback_rules.max_consecutive_failures, 10);
        assert!(!policy.rollback_rules.auto_rollback);
        assert_eq!(policy.created_at, Some(ts));
    }

    #[test]
    fn rollout_policy_builder_partial_overrides() {
        let policy = RolloutPolicy::builder().canary_percent(50).build();
        assert_eq!(policy.canary_percent, 50);
        // Others should be defaults
        assert_eq!(policy.min_canary_duration_secs, 300);
        assert_eq!(
            policy.success_thresholds.min_success_rate_bps,
            SuccessThresholds::default().min_success_rate_bps
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-type validation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn manifest_with_all_channels() {
        for channel in ["stable", "canary", "beta", "nightly", "dev"] {
            let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
                .digest(test_digest())
                .channel(channel)
                .min_host_version("0.1.0")
                .signed_by("test")
                .signature(test_signature())
                .build()
                .unwrap();
            assert_eq!(manifest.channel, channel);
        }
    }

    #[test]
    fn manifest_signature_propagation() {
        // Signature with invalid algorithm should bubble up through manifest validation
        let mut sig = test_signature();
        sig.algorithm = "hmac".to_string();
        let mut manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        manifest.signature = sig;
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("algorithm"));
    }

    #[test]
    fn policy_full_serde_roundtrip_with_timestamp() {
        let policy = RolloutPolicy::builder()
            .canary_percent(20)
            .min_canary_duration_secs(600)
            .success_thresholds(SuccessThresholds::new(9800, 200, 50, 120))
            .rollback_rules(RollbackRules::new(500, 3, 10, 60, true))
            .created_at(chrono::Utc::now())
            .build();

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: RolloutPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseManifest builder edge cases (expanded)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn builder_digest_override_keeps_last() {
        let digest1 = format!("blake3-256:{}", "b".repeat(64));
        let digest2 = format!("blake3-256:{}", "c".repeat(64));
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(&digest1)
            .digest(&digest2)
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.digest, digest2);
    }

    #[test]
    fn builder_signed_by_override_keeps_last() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("first@example.com")
            .signed_by("second@example.com")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.signed_by, "second@example.com");
    }

    #[test]
    fn builder_min_host_version_override() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .min_host_version("2.0.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.min_host_version, "2.0.0");
    }

    #[test]
    fn builder_signature_override() {
        let sig1 = ReleaseSignature::new("key-001", "sig-a", vec!["f".to_string()]);
        let sig2 = ReleaseSignature::new("key-002", "sig-b", vec!["g".to_string()]);
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(sig1)
            .signature(sig2)
            .build()
            .unwrap();
        assert_eq!(manifest.signature.key_id, "key-002");
    }

    #[test]
    fn builder_add_cap_after_required_caps_appends() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .required_caps(vec!["cap1".to_string()])
            .add_required_cap("cap2")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.required_caps, vec!["cap1", "cap2"]);
    }

    #[test]
    fn builder_no_digest_fails_validation() {
        // Builder starts with empty digest — build should fail
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn builder_no_min_host_version_fails() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .signed_by("test")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    #[test]
    fn builder_no_signed_by_fails() {
        let result = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signature(test_signature())
            .build();
        assert!(matches!(result, Err(ReleaseError::InvalidManifest { .. })));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseManifest Debug coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_manifest_debug_format() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        let debug = format!("{manifest:?}");
        assert!(debug.contains("ReleaseManifest"));
        assert!(debug.contains("1.0.0"));
    }

    #[test]
    fn release_manifest_builder_debug_format() {
        let builder = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .channel("canary");
        let debug = format!("{builder:?}");
        assert!(debug.contains("ReleaseManifestBuilder"));
        assert!(debug.contains("canary"));
    }

    #[test]
    fn release_manifest_builder_clone() {
        let builder = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .channel("canary")
            .add_required_cap("net:http");
        let cloned = builder.clone();
        // Use original after clone to avoid redundant_clone
        let m1 = builder
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        let m2 = cloned
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(m1, m2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseSignature expanded tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_signature_multiple_signed_fields() {
        let sig = ReleaseSignature::new(
            "key-abc",
            "deadbeef",
            vec![
                "connector_id".to_string(),
                "version".to_string(),
                "digest".to_string(),
                "channel".to_string(),
                "min_host_version".to_string(),
            ],
        );
        assert_eq!(sig.signed_fields.len(), 5);
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn release_signature_debug_format() {
        let sig = test_signature();
        let debug = format!("{sig:?}");
        assert!(debug.contains("ReleaseSignature"));
        assert!(debug.contains("ed25519"));
    }

    #[test]
    fn release_signature_deserialize_from_json_value() {
        let value = serde_json::json!({
            "algorithm": "ed25519",
            "key_id": "k1",
            "signature": "s1",
            "signed_fields": ["a", "b"]
        });
        let sig: ReleaseSignature = serde_json::from_value(value).unwrap();
        assert_eq!(sig.key_id, "k1");
        assert_eq!(sig.signed_fields.len(), 2);
    }

    #[test]
    fn release_signature_json_field_names() {
        let sig = test_signature();
        let value = serde_json::to_value(&sig).unwrap();
        assert!(value.get("algorithm").is_some());
        assert!(value.get("key_id").is_some());
        assert!(value.get("signature").is_some());
        assert!(value.get("signed_fields").is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RolloutPolicy validation edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollout_policy_validation_success_thresholds_overflow() {
        let policy = RolloutPolicy {
            success_thresholds: SuccessThresholds::new(15000, 500, 100, 300),
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollout_policy_validation_rollback_rules_zero_failures() {
        let policy = RolloutPolicy {
            rollback_rules: RollbackRules::new(2000, 0, 10, 60, true),
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollout_policy_validation_rollback_error_overflow() {
        let policy = RolloutPolicy {
            rollback_rules: RollbackRules::new(15000, 5, 10, 60, true),
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(ReleaseError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rollout_policy_debug_format() {
        let policy = RolloutPolicy::default();
        let debug = format!("{policy:?}");
        assert!(debug.contains("RolloutPolicy"));
        assert!(debug.contains("canary_percent"));
    }

    #[test]
    fn rollout_policy_builder_debug_format() {
        let builder = RolloutPolicy::builder().canary_percent(20);
        let debug = format!("{builder:?}");
        assert!(debug.contains("RolloutPolicyBuilder"));
    }

    #[test]
    fn rollout_policy_builder_clone() {
        let builder = RolloutPolicy::builder()
            .canary_percent(33)
            .min_canary_duration_secs(120);
        let cloned = builder.clone();
        let p1 = builder.build();
        let p2 = cloned.build();
        assert_eq!(p1, p2);
    }

    #[test]
    fn rollout_policy_json_field_names() {
        let policy = RolloutPolicy::default();
        let value = serde_json::to_value(&policy).unwrap();
        assert!(value.get("format").is_some());
        assert!(value.get("schema_version").is_some());
        assert!(value.get("canary_percent").is_some());
        assert!(value.get("min_canary_duration_secs").is_some());
        assert!(value.get("success_thresholds").is_some());
        assert!(value.get("rollback_rules").is_some());
    }

    #[test]
    fn rollout_policy_deserialize_from_json_value() {
        let value = serde_json::json!({
            "format": "fcp-rollout-policy",
            "schema_version": "1.0",
            "canary_percent": 5,
            "min_canary_duration_secs": 120,
            "success_thresholds": {
                "min_success_rate_bps": 9500,
                "max_error_rate_bps": 500,
                "min_samples": 100,
                "window_secs": 300
            },
            "rollback_rules": {
                "max_error_rate_bps": 2000,
                "max_consecutive_failures": 5,
                "min_samples": 10,
                "window_secs": 60,
                "auto_rollback": true
            }
        });
        let policy: RolloutPolicy = serde_json::from_value(value).unwrap();
        assert_eq!(policy.canary_percent, 5);
        assert_eq!(policy.min_canary_duration_secs, 120);
        assert!(policy.validate().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SuccessThresholds expanded tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn success_thresholds_custom_values() {
        let t = SuccessThresholds::new(8000, 2000, 500, 600);
        assert_eq!(t.min_success_rate_bps, 8000);
        assert_eq!(t.max_error_rate_bps, 2000);
        assert_eq!(t.min_samples, 500);
        assert_eq!(t.window_secs, 600);
    }

    #[test]
    fn success_thresholds_debug_format() {
        let t = SuccessThresholds::default();
        let debug = format!("{t:?}");
        assert!(debug.contains("SuccessThresholds"));
        assert!(debug.contains("9500"));
    }

    #[test]
    fn success_thresholds_both_invalid() {
        // success rate over MAX triggers first
        let t = SuccessThresholds::new(MAX_BPS + 1, MAX_BPS + 1, 1, 1);
        let err = t.validate().unwrap_err();
        assert!(err.to_string().contains("min_success_rate_bps"));
    }

    #[test]
    fn success_thresholds_max_error_only_invalid() {
        let t = SuccessThresholds::new(9500, MAX_BPS + 1, 100, 300);
        let err = t.validate().unwrap_err();
        assert!(err.to_string().contains("max_error_rate_bps"));
    }

    #[test]
    fn success_thresholds_rate_percent_fractional() {
        // 9999 bps = 99.99%
        let t = SuccessThresholds::new(9999, 1, 1, 1);
        assert!((t.success_rate_percent() - 99.99).abs() < f64::EPSILON);
        assert!((t.error_rate_percent() - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn success_thresholds_json_field_names() {
        let t = SuccessThresholds::default();
        let value = serde_json::to_value(&t).unwrap();
        assert!(value.get("min_success_rate_bps").is_some());
        assert!(value.get("max_error_rate_bps").is_some());
        assert!(value.get("min_samples").is_some());
        assert!(value.get("window_secs").is_some());
    }

    #[test]
    fn success_thresholds_deserialize_from_json_value() {
        let value = serde_json::json!({
            "min_success_rate_bps": 8500,
            "max_error_rate_bps": 1500,
            "min_samples": 42,
            "window_secs": 180
        });
        let t: SuccessThresholds = serde_json::from_value(value).unwrap();
        assert_eq!(t.min_success_rate_bps, 8500);
        assert_eq!(t.max_error_rate_bps, 1500);
        assert_eq!(t.min_samples, 42);
        assert_eq!(t.window_secs, 180);
    }

    #[test]
    fn success_thresholds_min_samples_zero_validates() {
        let t = SuccessThresholds::new(9500, 500, 0, 300);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn success_thresholds_window_secs_zero_validates() {
        let t = SuccessThresholds::new(9500, 500, 100, 0);
        assert!(t.validate().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RollbackRules expanded tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rollback_rules_custom_values() {
        let r = RollbackRules::new(3000, 10, 20, 120, false);
        assert_eq!(r.max_error_rate_bps, 3000);
        assert_eq!(r.max_consecutive_failures, 10);
        assert_eq!(r.min_samples, 20);
        assert_eq!(r.window_secs, 120);
        assert!(!r.auto_rollback);
    }

    #[test]
    fn rollback_rules_debug_format() {
        let r = RollbackRules::default();
        let debug = format!("{r:?}");
        assert!(debug.contains("RollbackRules"));
        assert!(debug.contains("auto_rollback"));
    }

    #[test]
    fn rollback_rules_zero_error_rate_valid() {
        let r = RollbackRules::new(0, 1, 1, 1, true);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rollback_rules_large_consecutive_failures() {
        let r = RollbackRules::new(2000, u32::MAX, 10, 60, true);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rollback_rules_rate_percent_fractional() {
        let r = RollbackRules::new(1, 1, 1, 1, true);
        assert!((r.error_rate_percent() - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn rollback_rules_json_field_names() {
        let r = RollbackRules::default();
        let value = serde_json::to_value(&r).unwrap();
        assert!(value.get("max_error_rate_bps").is_some());
        assert!(value.get("max_consecutive_failures").is_some());
        assert!(value.get("min_samples").is_some());
        assert!(value.get("window_secs").is_some());
        assert!(value.get("auto_rollback").is_some());
    }

    #[test]
    fn rollback_rules_deserialize_from_json_value() {
        let value = serde_json::json!({
            "max_error_rate_bps": 1234,
            "max_consecutive_failures": 7,
            "min_samples": 15,
            "window_secs": 90,
            "auto_rollback": false
        });
        let r: RollbackRules = serde_json::from_value(value).unwrap();
        assert_eq!(r.max_error_rate_bps, 1234);
        assert_eq!(r.max_consecutive_failures, 7);
        assert!(!r.auto_rollback);
    }

    #[test]
    fn rollback_rules_min_samples_zero_validates() {
        let r = RollbackRules::new(2000, 5, 0, 60, true);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rollback_rules_window_secs_zero_validates() {
        let r = RollbackRules::new(2000, 5, 10, 0, true);
        assert!(r.validate().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReleaseError expanded tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn release_error_not_found_with_different_connectors() {
        let err = ReleaseError::NotFound {
            connector_id: ConnectorId::from_static("slack:chat:v2"),
            version: "2.1.0".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("slack:chat:v2"));
        assert!(msg.contains("2.1.0"));
    }

    #[test]
    fn release_error_variants_not_equal_across_types() {
        let a = ReleaseError::InvalidManifest {
            reason: "test".to_string(),
        };
        let b = ReleaseError::InvalidPolicy {
            reason: "test".to_string(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn release_error_signature_failed_clone() {
        let err = ReleaseError::SignatureVerificationFailed {
            reason: "bad key".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn release_error_not_found_clone() {
        let err = ReleaseError::NotFound {
            connector_id: test_connector_id(),
            version: "4.0.0".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn release_error_debug_format() {
        let err = ReleaseError::InvalidManifest {
            reason: "bad digest".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidManifest"));
        assert!(debug.contains("bad digest"));
    }

    #[test]
    fn release_error_not_found_debug_format() {
        let err = ReleaseError::NotFound {
            connector_id: test_connector_id(),
            version: "5.0.0".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("NotFound"));
        assert!(debug.contains("5.0.0"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-type and integration-style tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn manifest_valid_after_clone_and_modification() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        let mut modified = manifest.clone();
        // Use original to verify it's still valid
        assert!(manifest.validate().is_ok());
        modified.channel = "canary".to_string();
        assert!(modified.validate().is_ok());
        assert_ne!(manifest.channel, modified.channel);
    }

    #[test]
    fn policy_valid_after_clone_and_modification() {
        let policy = RolloutPolicy::default();
        let mut modified = policy.clone();
        // Use original
        assert!(policy.validate().is_ok());
        modified.canary_percent = 50;
        assert!(modified.validate().is_ok());
        assert_ne!(policy.canary_percent, modified.canary_percent);
    }

    #[test]
    fn rollout_policy_success_rate_percent_custom() {
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9750, 250, 50, 120))
            .rollback_rules(RollbackRules::new(500, 3, 5, 30, true))
            .build();
        assert!((policy.success_rate_percent() - 97.5).abs() < f64::EPSILON);
    }

    #[test]
    fn rollout_policy_error_rate_percent_custom() {
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9500, 500, 50, 120))
            .rollback_rules(RollbackRules::new(1500, 3, 5, 30, true))
            .build();
        assert!((policy.error_rate_percent() - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn manifest_serde_json_to_value_and_back() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "3.0.0")
            .digest(test_digest())
            .channel("beta")
            .min_host_version("1.2.0")
            .signed_by("ci@build.com")
            .add_required_cap("secret:read")
            .signature(test_signature())
            .build()
            .unwrap();

        let value = serde_json::to_value(&manifest).unwrap();
        let decoded: ReleaseManifest = serde_json::from_value(value).unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn policy_serde_json_to_value_and_back() {
        let policy = RolloutPolicy::builder()
            .canary_percent(75)
            .min_canary_duration_secs(1800)
            .build();
        let value = serde_json::to_value(&policy).unwrap();
        let decoded: RolloutPolicy = serde_json::from_value(value).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn manifest_digest_hex_various_patterns() {
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(format!("blake3-256:{}", "0123456789abcdef".repeat(4)))
            .min_host_version("0.1.0")
            .signed_by("test")
            .signature(test_signature())
            .build()
            .unwrap();
        let hex = manifest.digest_hex().unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("0123"));
    }

    #[test]
    fn rollout_policy_canary_percent_at_each_boundary() {
        for pct in [0_u8, 1, 50, 99, 100] {
            let policy = RolloutPolicy {
                canary_percent: pct,
                ..Default::default()
            };
            assert!(policy.validate().is_ok(), "should be valid at {pct}%");
        }
    }

    #[test]
    fn rollout_policy_threshold_consistency_boundary() {
        // Exactly equal promotion error and rollback error rates: valid
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9000, 1000, 50, 120))
            .rollback_rules(RollbackRules::new(1000, 3, 5, 30, true))
            .build();
        assert!(policy.validate().is_ok());

        // One bps above: invalid
        let policy2 = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9000, 1001, 50, 120))
            .rollback_rules(RollbackRules::new(1000, 3, 5, 30, true))
            .build();
        assert!(policy2.validate().is_err());
    }

    #[test]
    fn manifest_with_many_required_caps() {
        let caps: Vec<String> = (0..20).map(|i| format!("cap:{i}")).collect();
        let manifest = ReleaseManifest::builder(test_connector_id(), "1.0.0")
            .digest(test_digest())
            .min_host_version("0.1.0")
            .signed_by("test")
            .required_caps(caps)
            .signature(test_signature())
            .build()
            .unwrap();
        assert_eq!(manifest.required_caps.len(), 20);
        assert_eq!(manifest.required_caps[19], "cap:19");
    }

    #[test]
    fn manifest_version_any_string() {
        // Version can be any non-empty string
        for ver in ["0.0.1-alpha", "2025.03.09", "v1", "nightly-20260309"] {
            let manifest = ReleaseManifest::builder(test_connector_id(), ver)
                .digest(test_digest())
                .min_host_version("0.1.0")
                .signed_by("test")
                .signature(test_signature())
                .build()
                .unwrap();
            assert_eq!(manifest.version, ver);
        }
    }

    #[test]
    fn release_error_source_is_none() {
        let err = ReleaseError::InvalidManifest {
            reason: "test".to_string(),
        };
        let std_err: &dyn std::error::Error = &err;
        assert!(std_err.source().is_none());
    }

    #[test]
    fn rollout_policy_builder_min_canary_duration_override() {
        let policy = RolloutPolicy::builder()
            .min_canary_duration_secs(60)
            .min_canary_duration_secs(900)
            .build();
        assert_eq!(policy.min_canary_duration_secs, 900);
    }

    #[test]
    fn rollout_policy_builder_success_thresholds_override() {
        let policy = RolloutPolicy::builder()
            .success_thresholds(SuccessThresholds::new(9000, 1000, 50, 120))
            .success_thresholds(SuccessThresholds::new(9800, 200, 200, 600))
            .build();
        assert_eq!(policy.success_thresholds.min_success_rate_bps, 9800);
    }

    #[test]
    fn rollout_policy_builder_rollback_rules_override() {
        let policy = RolloutPolicy::builder()
            .rollback_rules(RollbackRules::new(1000, 3, 5, 30, true))
            .rollback_rules(RollbackRules::new(3000, 10, 20, 120, false))
            .build();
        assert_eq!(policy.rollback_rules.max_error_rate_bps, 3000);
        assert!(!policy.rollback_rules.auto_rollback);
    }
}
