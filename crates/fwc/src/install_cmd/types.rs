//! Install command types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for connector installation,
//! enabling automation and CI/CD integration.

use serde::{Deserialize, Serialize};

/// Installation result output record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallOutput {
    /// Connector ID that was installed.
    pub connector_id: String,

    /// Version that was installed.
    pub version: String,

    /// Target platform/arch.
    pub target: String,

    /// Zone where connector was installed.
    pub zone_id: String,

    /// Manifest hash (sha256:...).
    pub manifest_hash: String,

    /// Binary hash (sha256:...).
    pub binary_hash: String,

    /// Object ID of the manifest in the mesh store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_object_id: Option<String>,

    /// Object ID of the binary in the mesh store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_object_id: Option<String>,

    /// Verification details.
    pub verification: VerificationDetails,

    /// Installation timestamp (Unix seconds).
    pub installed_at: u64,

    /// ISO-8601 formatted timestamp for human readability.
    pub installed_at_iso: String,
}

/// Verification details for an installation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    /// Whether publisher signature was verified.
    pub publisher_signature_verified: bool,

    /// Whether registry signature was verified.
    pub registry_signature_verified: bool,

    /// Number of publisher signatures that passed threshold.
    pub publisher_signatures_valid: u8,

    /// Required publisher signature threshold.
    pub publisher_threshold: u8,

    /// Whether supply chain policy was satisfied.
    pub supply_chain_policy_satisfied: bool,

    /// Whether capability ceiling was respected.
    pub capability_ceiling_respected: bool,

    /// List of verified attestation types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_attestations: Vec<String>,

    /// SLSA level if verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slsa_level: Option<u8>,

    /// Supply-chain reason code for the final decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supply_chain_reason_code: Option<String>,

    /// Deterministic evidence bundle hash for audit and CI correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supply_chain_evidence_digest: Option<String>,

    /// Artifact digest used for supply-chain verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supply_chain_artifact_digest: Option<String>,
}

impl Default for VerificationDetails {
    fn default() -> Self {
        Self {
            publisher_signature_verified: false,
            registry_signature_verified: false,
            publisher_signatures_valid: 0,
            publisher_threshold: 0,
            supply_chain_policy_satisfied: true,
            capability_ceiling_respected: true,
            verified_attestations: Vec::new(),
            slsa_level: None,
            supply_chain_reason_code: None,
            supply_chain_evidence_digest: None,
            supply_chain_artifact_digest: None,
        }
    }
}

/// Install error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallError {
    /// Error code (FCP-XXXX).
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Recovery hints for operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,

    /// Connector ID if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,

    /// Version if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for InstallError {}

#[allow(dead_code)] // Error constructors for future verification features
impl InstallError {
    /// Create a "connector not found" error.
    #[must_use]
    pub fn connector_not_found(connector_id: &str) -> Self {
        Self {
            code: "FCP-4010".to_string(),
            message: format!("Connector '{connector_id}' not found in registry"),
            hints: vec![
                "Verify the connector ID is correct".to_string(),
                "Check if the connector is published to the registry".to_string(),
                "Run 'fcp search <query>' to find available connectors".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "version not found" error.
    #[must_use]
    pub fn version_not_found(connector_id: &str, version: &str) -> Self {
        Self {
            code: "FCP-4011".to_string(),
            message: format!("Version '{version}' not found for connector '{connector_id}'"),
            hints: vec![
                "Verify the version string is correct".to_string(),
                "Run 'fcp info <connector>' to see available versions".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: Some(version.to_string()),
        }
    }

    /// Create a "signature verification failed" error.
    #[must_use]
    pub fn signature_verification_failed(connector_id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-4012".to_string(),
            message: format!("Signature verification failed for '{connector_id}': {reason}"),
            hints: vec![
                "The connector may have been tampered with".to_string(),
                "Check if your trust policy keys are up to date".to_string(),
                "Contact the connector publisher if this persists".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "binary checksum mismatch" error.
    #[must_use]
    pub fn binary_checksum_mismatch(connector_id: &str, expected: &str, actual: &str) -> Self {
        Self {
            code: "FCP-4013".to_string(),
            message: format!(
                "Binary checksum mismatch for '{connector_id}': expected {expected}, got {actual}"
            ),
            hints: vec![
                "The binary may have been corrupted or tampered with".to_string(),
                "Try re-downloading the connector".to_string(),
                "Contact the connector publisher if this persists".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "capability ceiling violation" error.
    #[must_use]
    pub fn capability_ceiling_violation(connector_id: &str, capability: &str) -> Self {
        Self {
            code: "FCP-4014".to_string(),
            message: format!(
                "Connector '{connector_id}' requires capability '{capability}' which exceeds zone ceiling"
            ),
            hints: vec![
                "The connector requires capabilities not allowed in this zone".to_string(),
                "Check zone policy capability_ceiling settings".to_string(),
                "Contact zone administrator to expand capability ceiling".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "supply chain policy violation" error.
    #[must_use]
    pub fn supply_chain_policy_violation(connector_id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-4015".to_string(),
            message: format!("Supply chain policy violation for '{connector_id}': {reason}"),
            hints: vec![
                "The connector does not meet supply chain requirements".to_string(),
                "Check if transparency log or attestations are required".to_string(),
                "Use --skip-supply-chain to bypass (not recommended)".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "target mismatch" error.
    #[must_use]
    pub fn target_mismatch(connector_id: &str, expected: &str, actual: &str) -> Self {
        Self {
            code: "FCP-4016".to_string(),
            message: format!(
                "Target mismatch for '{connector_id}': expected {expected}, got {actual}"
            ),
            hints: vec![
                format!("The connector binary is built for {actual}"),
                format!("Your system requires {expected}"),
                "Check if a compatible binary is available".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }

    /// Create a "zone not found" error.
    #[must_use]
    pub fn zone_not_found(zone_id: &str) -> Self {
        Self {
            code: "FCP-4001".to_string(),
            message: format!("Zone '{zone_id}' not found or not accessible"),
            hints: vec![
                "Verify the zone ID is correct".to_string(),
                "Check if you have access to this zone".to_string(),
                "Run 'fcp doctor --zone <zone>' to diagnose".to_string(),
            ],
            connector_id: None,
            version: None,
        }
    }

    /// Create a "mirror failed" error.
    #[must_use]
    pub fn mirror_failed(connector_id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-5020".to_string(),
            message: format!("Failed to mirror connector '{connector_id}' to mesh store: {reason}"),
            hints: vec![
                "Check mesh node connectivity".to_string(),
                "Verify object store is writable".to_string(),
                "Run 'fcp doctor --zone <zone>' to check storage".to_string(),
            ],
            connector_id: Some(connector_id.to_string()),
            version: None,
        }
    }
}

/// Installation progress event for streaming output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgress {
    /// Current phase of installation.
    pub phase: InstallPhase,

    /// Human-readable message.
    pub message: String,

    /// Progress percentage (0-100) if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<u8>,
}

/// Installation phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    /// Fetching manifest from registry.
    FetchingManifest,
    /// Verifying manifest signatures.
    VerifyingManifest,
    /// Fetching binary from registry.
    FetchingBinary,
    /// Verifying binary checksum.
    VerifyingBinary,
    /// Checking supply chain policy.
    CheckingSupplyChain,
    /// Mirroring to mesh store.
    Mirroring,
    /// Emitting audit event.
    EmittingAudit,
    /// Installation complete.
    Complete,
}

impl InstallPhase {
    /// Get human-readable label for this phase.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FetchingManifest => "Fetching manifest",
            Self::VerifyingManifest => "Verifying manifest",
            Self::FetchingBinary => "Fetching binary",
            Self::VerifyingBinary => "Verifying binary",
            Self::CheckingSupplyChain => "Checking supply chain",
            Self::Mirroring => "Mirroring to store",
            Self::EmittingAudit => "Emitting audit event",
            Self::Complete => "Complete",
        }
    }

    /// Get ANSI color code for this phase.
    #[must_use]
    pub const fn color(self) -> &'static str {
        match self {
            Self::Complete => "\x1b[32m", // Green
            _ => "\x1b[36m",              // Cyan
        }
    }

    /// Get symbol for this phase.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::FetchingManifest | Self::FetchingBinary => "↓",
            Self::VerifyingManifest | Self::VerifyingBinary => "✓",
            Self::CheckingSupplyChain => "⛓",
            Self::Mirroring => "→",
            Self::EmittingAudit => "📝",
            Self::Complete => "✔",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_output_json_snapshot() {
        let output = InstallOutput {
            connector_id: "fcp.telegram:base:v1".to_string(),
            version: "1.0.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            zone_id: "z:work".to_string(),
            manifest_hash: "sha256:abc123".to_string(),
            binary_hash: "sha256:def456".to_string(),
            manifest_object_id: Some("obj:manifest:123".to_string()),
            binary_object_id: Some("obj:binary:456".to_string()),
            verification: VerificationDetails {
                publisher_signature_verified: true,
                registry_signature_verified: true,
                publisher_signatures_valid: 2,
                publisher_threshold: 2,
                supply_chain_policy_satisfied: true,
                capability_ceiling_respected: true,
                verified_attestations: vec!["in-toto".to_string()],
                slsa_level: Some(3),
                supply_chain_reason_code: Some("verified".to_string()),
                supply_chain_evidence_digest: Some("blake3-256:abcd".to_string()),
                supply_chain_artifact_digest: Some("blake3-256:efgh".to_string()),
            },
            installed_at: 1_700_000_000,
            installed_at_iso: "2023-11-14T22:13:20Z".to_string(),
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("\"connector_id\": \"fcp.telegram:base:v1\""));
        assert!(json.contains("\"publisher_signature_verified\": true"));
        assert!(json.contains("\"slsa_level\": 3"));

        // Verify roundtrip
        let parsed: InstallOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.telegram:base:v1");
        assert_eq!(parsed.verification.slsa_level, Some(3));
    }

    #[test]
    fn install_error_connector_not_found() {
        let err = InstallError::connector_not_found("fcp.unknown:base:v1");
        assert_eq!(err.code, "FCP-4010");
        assert!(err.message.contains("fcp.unknown:base:v1"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn install_error_signature_verification_failed() {
        let err = InstallError::signature_verification_failed(
            "fcp.telegram:base:v1",
            "invalid signature",
        );
        assert_eq!(err.code, "FCP-4012");
        assert!(err.message.contains("invalid signature"));
    }

    #[test]
    fn install_phase_labels() {
        assert_eq!(InstallPhase::FetchingManifest.label(), "Fetching manifest");
        assert_eq!(InstallPhase::Complete.label(), "Complete");
    }

    #[test]
    fn verification_details_default() {
        let details = VerificationDetails::default();
        assert!(!details.publisher_signature_verified);
        assert!(details.supply_chain_policy_satisfied);
        assert!(details.verified_attestations.is_empty());
    }

    // ── InstallError constructors ───────────────────────────────

    #[test]
    fn install_error_version_not_found() {
        let err = InstallError::version_not_found("fcp.test:v1", "9.9.9");
        assert_eq!(err.code, "FCP-4011");
        assert!(err.message.contains("9.9.9"));
        assert!(err.message.contains("fcp.test:v1"));
        assert_eq!(err.connector_id.as_deref(), Some("fcp.test:v1"));
        assert_eq!(err.version.as_deref(), Some("9.9.9"));
    }

    #[test]
    fn install_error_binary_checksum_mismatch() {
        let err = InstallError::binary_checksum_mismatch("fcp.test:v1", "sha256:abc", "sha256:def");
        assert_eq!(err.code, "FCP-4013");
        assert!(err.message.contains("sha256:abc"));
        assert!(err.message.contains("sha256:def"));
    }

    #[test]
    fn install_error_capability_ceiling_violation() {
        let err = InstallError::capability_ceiling_violation("fcp.test:v1", "system.exec");
        assert_eq!(err.code, "FCP-4014");
        assert!(err.message.contains("system.exec"));
        assert!(err.message.contains("exceeds zone ceiling"));
    }

    #[test]
    fn install_error_supply_chain_policy_violation() {
        let err =
            InstallError::supply_chain_policy_violation("fcp.test:v1", "transparency log missing");
        assert_eq!(err.code, "FCP-4015");
        assert!(err.message.contains("transparency log missing"));
    }

    #[test]
    fn install_error_target_mismatch() {
        let err = InstallError::target_mismatch("fcp.test:v1", "linux/amd64", "darwin/arm64");
        assert_eq!(err.code, "FCP-4016");
        assert!(err.message.contains("linux/amd64"));
        assert!(err.message.contains("darwin/arm64"));
        assert_eq!(err.hints.len(), 3);
    }

    #[test]
    fn install_error_zone_not_found() {
        let err = InstallError::zone_not_found("z:invalid");
        assert_eq!(err.code, "FCP-4001");
        assert!(err.message.contains("z:invalid"));
        assert!(err.connector_id.is_none());
        assert!(err.version.is_none());
    }

    #[test]
    fn install_error_mirror_failed() {
        let err = InstallError::mirror_failed("fcp.test:v1", "connection refused");
        assert_eq!(err.code, "FCP-5020");
        assert!(err.message.contains("connection refused"));
        assert!(err.message.contains("mesh store"));
    }

    // ── InstallError Display ────────────────────────────────────

    #[test]
    fn install_error_display_format() {
        let err = InstallError::connector_not_found("fcp.test:v1");
        let display = format!("{err}");
        assert!(display.starts_with("FCP-4010: "));
        assert!(display.contains("fcp.test:v1"));
    }

    #[test]
    fn install_error_is_std_error() {
        let err = InstallError::connector_not_found("fcp.test:v1");
        let _: &dyn std::error::Error = &err;
    }

    // ── InstallError JSON serialization ─────────────────────────

    #[test]
    fn install_error_json_roundtrip() {
        let err = InstallError::connector_not_found("fcp.test:v1");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: InstallError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, err.code);
        assert_eq!(parsed.message, err.message);
        assert_eq!(parsed.hints.len(), err.hints.len());
    }

    #[test]
    fn install_error_json_skips_none_fields() {
        let err = InstallError::zone_not_found("z:test");
        let json = serde_json::to_string(&err).unwrap();
        // connector_id and version are None, should be skipped
        assert!(!json.contains("connector_id"));
        assert!(!json.contains("version"));
    }

    #[test]
    fn install_error_json_includes_some_fields() {
        let err = InstallError::version_not_found("fcp.test:v1", "2.0.0");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"connector_id\""));
        assert!(json.contains("\"version\""));
    }

    // ── InstallPhase tests ──────────────────────────────────────

    #[test]
    fn install_phase_all_labels() {
        let phases = [
            (InstallPhase::FetchingManifest, "Fetching manifest"),
            (InstallPhase::VerifyingManifest, "Verifying manifest"),
            (InstallPhase::FetchingBinary, "Fetching binary"),
            (InstallPhase::VerifyingBinary, "Verifying binary"),
            (InstallPhase::CheckingSupplyChain, "Checking supply chain"),
            (InstallPhase::Mirroring, "Mirroring to store"),
            (InstallPhase::EmittingAudit, "Emitting audit event"),
            (InstallPhase::Complete, "Complete"),
        ];
        for (phase, expected) in phases {
            assert_eq!(phase.label(), expected, "wrong label for {phase:?}");
        }
    }

    #[test]
    fn install_phase_all_symbols() {
        // Fetch phases use ↓
        assert_eq!(InstallPhase::FetchingManifest.symbol(), "↓");
        assert_eq!(InstallPhase::FetchingBinary.symbol(), "↓");
        // Verify phases use ✓
        assert_eq!(InstallPhase::VerifyingManifest.symbol(), "✓");
        assert_eq!(InstallPhase::VerifyingBinary.symbol(), "✓");
        // Supply chain uses ⛓
        assert_eq!(InstallPhase::CheckingSupplyChain.symbol(), "⛓");
        // Mirror uses →
        assert_eq!(InstallPhase::Mirroring.symbol(), "→");
        // Complete uses ✔
        assert_eq!(InstallPhase::Complete.symbol(), "✔");
    }

    #[test]
    fn install_phase_colors() {
        // Complete is green
        assert_eq!(InstallPhase::Complete.color(), "\x1b[32m");
        // All others are cyan
        assert_eq!(InstallPhase::FetchingManifest.color(), "\x1b[36m");
        assert_eq!(InstallPhase::VerifyingBinary.color(), "\x1b[36m");
        assert_eq!(InstallPhase::Mirroring.color(), "\x1b[36m");
    }

    #[test]
    fn install_phase_equality() {
        assert_eq!(InstallPhase::Complete, InstallPhase::Complete);
        assert_ne!(InstallPhase::Complete, InstallPhase::Mirroring);
    }

    #[test]
    fn install_phase_serde_roundtrip() {
        let phase = InstallPhase::CheckingSupplyChain;
        let json = serde_json::to_string(&phase).unwrap();
        assert_eq!(json, "\"checking_supply_chain\"");
        let parsed: InstallPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, phase);
    }

    #[test]
    fn install_phase_all_serde_roundtrips() {
        let phases = [
            InstallPhase::FetchingManifest,
            InstallPhase::VerifyingManifest,
            InstallPhase::FetchingBinary,
            InstallPhase::VerifyingBinary,
            InstallPhase::CheckingSupplyChain,
            InstallPhase::Mirroring,
            InstallPhase::EmittingAudit,
            InstallPhase::Complete,
        ];
        for phase in phases {
            let json = serde_json::to_string(&phase).unwrap();
            let parsed: InstallPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, phase);
        }
    }

    // ── InstallProgress tests ───────────────────────────────────

    #[test]
    fn install_progress_json_roundtrip() {
        let progress = InstallProgress {
            phase: InstallPhase::VerifyingManifest,
            message: "checking signatures".to_string(),
            progress_percent: Some(50),
        };
        let json = serde_json::to_string(&progress).unwrap();
        let parsed: InstallProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.phase, InstallPhase::VerifyingManifest);
        assert_eq!(parsed.message, "checking signatures");
        assert_eq!(parsed.progress_percent, Some(50));
    }

    #[test]
    fn install_progress_without_percent() {
        let progress = InstallProgress {
            phase: InstallPhase::FetchingManifest,
            message: "downloading".to_string(),
            progress_percent: None,
        };
        let json = serde_json::to_string(&progress).unwrap();
        // progress_percent should be omitted
        assert!(!json.contains("progress_percent"));
    }

    // ── VerificationDetails tests ───────────────────────────────

    #[test]
    fn verification_details_full_json_roundtrip() {
        let details = VerificationDetails {
            publisher_signature_verified: true,
            registry_signature_verified: true,
            publisher_signatures_valid: 3,
            publisher_threshold: 2,
            supply_chain_policy_satisfied: true,
            capability_ceiling_respected: true,
            verified_attestations: vec!["in-toto".to_string(), "sigstore".to_string()],
            slsa_level: Some(3),
            supply_chain_reason_code: Some("verified".to_string()),
            supply_chain_evidence_digest: Some("blake3-256:abcd".to_string()),
            supply_chain_artifact_digest: Some("blake3-256:efgh".to_string()),
        };
        let json = serde_json::to_string(&details).unwrap();
        let parsed: VerificationDetails = serde_json::from_str(&json).unwrap();
        assert!(parsed.publisher_signature_verified);
        assert!(parsed.registry_signature_verified);
        assert_eq!(parsed.publisher_signatures_valid, 3);
        assert_eq!(parsed.publisher_threshold, 2);
        assert_eq!(parsed.verified_attestations.len(), 2);
        assert_eq!(parsed.slsa_level, Some(3));
        assert_eq!(parsed.supply_chain_reason_code.as_deref(), Some("verified"));
        assert_eq!(
            parsed.supply_chain_evidence_digest.as_deref(),
            Some("blake3-256:abcd")
        );
    }

    #[test]
    fn verification_details_minimal_json_skips_optional() {
        let details = VerificationDetails::default();
        let json = serde_json::to_string(&details).unwrap();
        // Empty verified_attestations should be skipped
        assert!(!json.contains("verified_attestations"));
        // None slsa_level should be skipped
        assert!(!json.contains("slsa_level"));
        assert!(!json.contains("supply_chain_reason_code"));
        assert!(!json.contains("supply_chain_evidence_digest"));
        assert!(!json.contains("supply_chain_artifact_digest"));
    }

    // ── InstallOutput tests ─────────────────────────────────────

    #[test]
    fn install_output_verify_only_json() {
        let output = InstallOutput {
            connector_id: "fcp.test:base:v1".to_string(),
            version: "1.0.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            zone_id: "z:work".to_string(),
            manifest_hash: "sha256:aaa".to_string(),
            binary_hash: "sha256:bbb".to_string(),
            manifest_object_id: None,
            binary_object_id: None,
            verification: VerificationDetails::default(),
            installed_at: 0,
            installed_at_iso: "1970-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        // Optional object IDs should be omitted
        assert!(!json.contains("manifest_object_id"));
        assert!(!json.contains("binary_object_id"));
    }

    #[test]
    fn install_output_with_object_ids_json() {
        let output = InstallOutput {
            connector_id: "fcp.test:base:v1".to_string(),
            version: "1.0.0".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            zone_id: "z:private".to_string(),
            manifest_hash: "sha256:111".to_string(),
            binary_hash: "sha256:222".to_string(),
            manifest_object_id: Some("obj:m:abc".to_string()),
            binary_object_id: Some("obj:b:def".to_string()),
            verification: VerificationDetails {
                publisher_signature_verified: true,
                registry_signature_verified: false,
                publisher_signatures_valid: 1,
                publisher_threshold: 1,
                supply_chain_policy_satisfied: true,
                capability_ceiling_respected: true,
                verified_attestations: Vec::new(),
                slsa_level: None,
                supply_chain_reason_code: Some("verified".to_string()),
                supply_chain_evidence_digest: Some("blake3-256:feed".to_string()),
                supply_chain_artifact_digest: Some("blake3-256:beef".to_string()),
            },
            installed_at: 1_700_000_000,
            installed_at_iso: "2023-11-14T22:13:20Z".to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"manifest_object_id\""));
        assert!(json.contains("\"binary_object_id\""));
        assert!(json.contains("\"supply_chain_evidence_digest\""));
    }

    #[test]
    fn install_output_full_roundtrip() {
        let output = InstallOutput {
            connector_id: "fcp.telegram:base:v1".to_string(),
            version: "1.0.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            zone_id: "z:work".to_string(),
            manifest_hash: "sha256:abc".to_string(),
            binary_hash: "sha256:def".to_string(),
            manifest_object_id: Some("obj:1".to_string()),
            binary_object_id: Some("obj:2".to_string()),
            verification: VerificationDetails {
                publisher_signature_verified: true,
                registry_signature_verified: true,
                publisher_signatures_valid: 2,
                publisher_threshold: 2,
                supply_chain_policy_satisfied: true,
                capability_ceiling_respected: true,
                verified_attestations: vec!["in-toto".to_string()],
                slsa_level: Some(2),
                supply_chain_reason_code: Some("verified".to_string()),
                supply_chain_evidence_digest: Some("blake3-256:cafe".to_string()),
                supply_chain_artifact_digest: Some("blake3-256:babe".to_string()),
            },
            installed_at: 12345,
            installed_at_iso: "2020-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: InstallOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, output.connector_id);
        assert_eq!(parsed.version, output.version);
        assert_eq!(parsed.target, output.target);
        assert_eq!(parsed.zone_id, output.zone_id);
        assert_eq!(parsed.installed_at, output.installed_at);
        assert_eq!(
            parsed.verification.publisher_signatures_valid,
            output.verification.publisher_signatures_valid
        );
    }

    // ── Hints content tests ─────────────────────────────────────

    #[test]
    fn all_error_types_have_hints() {
        let errors = [
            InstallError::connector_not_found("test"),
            InstallError::version_not_found("test", "1.0.0"),
            InstallError::signature_verification_failed("test", "reason"),
            InstallError::binary_checksum_mismatch("test", "a", "b"),
            InstallError::capability_ceiling_violation("test", "cap"),
            InstallError::supply_chain_policy_violation("test", "reason"),
            InstallError::target_mismatch("test", "a", "b"),
            InstallError::zone_not_found("z:test"),
            InstallError::mirror_failed("test", "reason"),
        ];
        for err in &errors {
            assert!(!err.hints.is_empty(), "error {} has no hints", err.code);
        }
    }

    #[test]
    fn error_codes_are_unique() {
        let codes: Vec<String> = vec![
            InstallError::connector_not_found("t").code,
            InstallError::version_not_found("t", "v").code,
            InstallError::signature_verification_failed("t", "r").code,
            InstallError::binary_checksum_mismatch("t", "a", "b").code,
            InstallError::capability_ceiling_violation("t", "c").code,
            InstallError::supply_chain_policy_violation("t", "r").code,
            InstallError::target_mismatch("t", "a", "b").code,
            InstallError::zone_not_found("z").code,
            InstallError::mirror_failed("t", "r").code,
        ];
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "duplicate error codes found");
    }
}
