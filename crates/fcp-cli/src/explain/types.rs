//! Explain report types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for decision explanation reports,
//! enabling automation and operator tooling integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete explain report for a `DecisionReceipt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// The request object ID that was evaluated.
    pub request_object_id: String,

    /// The decision outcome.
    pub decision: DecisionOutcome,

    /// Stable reason code (FCP-XXXX).
    pub reason_code: String,

    /// Operation ID associated with this decision (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,

    /// Retry-after hint in milliseconds (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,

    /// Human-readable reason code description.
    pub reason_description: String,

    /// Evidence objects that support this decision.
    pub evidence: Vec<EvidenceItem>,

    /// Optional human-readable explanation from the receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// Zone where the decision was made.
    pub zone_id: String,

    /// Signing node information.
    pub signed_by: SignerInfo,
}

impl ExplainReport {
    /// Schema version constant.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

/// Decision outcome (allow/deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionOutcome {
    Allow,
    Deny,
}

impl DecisionOutcome {
    /// Get ANSI color code for terminal output.
    #[must_use]
    pub const fn ansi_color(self) -> &'static str {
        match self {
            Self::Allow => "\x1b[32m", // Green
            Self::Deny => "\x1b[31m",  // Red
        }
    }

    /// Get symbol for terminal output.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Allow => "✓",
            Self::Deny => "✗",
        }
    }

    /// Reset ANSI color.
    #[must_use]
    pub const fn ansi_reset() -> &'static str {
        "\x1b[0m"
    }
}

/// Evidence item in the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Object ID (hex-encoded).
    pub object_id: String,

    /// Inferred type of evidence (capability, grant, checkpoint, etc.).
    pub evidence_type: EvidenceType,

    /// Human-readable description.
    pub description: String,
}

/// Type of evidence object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Capability token.
    CapabilityToken,
    /// Capability grant chain.
    CapabilityGrant,
    /// Zone checkpoint.
    ZoneCheckpoint,
    /// Revocation entry.
    Revocation,
    /// Policy object.
    Policy,
    /// Approval attestation.
    Approval,
    /// Request object.
    Request,
    /// Unknown/other evidence type.
    Unknown,
}

impl EvidenceType {
    /// Get a human-readable label for this evidence type.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CapabilityToken => "Capability Token",
            Self::CapabilityGrant => "Capability Grant",
            Self::ZoneCheckpoint => "Zone Checkpoint",
            Self::Revocation => "Revocation Entry",
            Self::Policy => "Policy Object",
            Self::Approval => "Approval Attestation",
            Self::Request => "Request Object",
            Self::Unknown => "Evidence Object",
        }
    }
}

/// Signer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    /// Node ID that signed the receipt.
    pub node_id: String,

    /// Timestamp when signed (Unix timestamp).
    pub signed_at: u64,
}

/// Reason code descriptions.
///
/// Maps FCP-XXXX codes to human-readable descriptions.
#[must_use]
pub fn reason_code_description(code: &str) -> &'static str {
    match code {
        // Success codes
        "FCP-0000" => "Request allowed - all checks passed",

        // Protocol errors (FCP-1xxx)
        "FCP-1001" => "Invalid request format",
        "FCP-1002" => "Malformed frame",
        "FCP-1003" => "Missing required field",
        "FCP-1004" => "Checksum mismatch",
        "FCP-1005" => "Protocol version mismatch",

        // Auth/Identity errors (FCP-2xxx)
        "FCP-2001" => "Unauthorized - no valid credentials",
        "FCP-2002" => "Token expired",
        "FCP-2003" => "Invalid signature",
        "FCP-2004" => "Principal not recognized",

        // Capability errors (FCP-3xxx)
        "FCP-3001" => "Capability denied - insufficient permissions",
        "FCP-3002" => "Rate limited - too many requests",
        "FCP-3003" => "Operation not granted by capability token",
        "FCP-3004" => "Resource not allowed by capability scope",
        "FCP-3005" => "Capability token revoked",

        // Zone/Topology/Provenance errors (FCP-4xxx)
        "FCP-4001" => "Zone violation - cross-zone access denied",
        "FCP-4002" => "Taint violation - data flow policy blocked",
        "FCP-4010" => "Provenance mismatch - origin zone not allowed",
        "FCP-4020" => "Expired capability token",
        "FCP-4030" => "Revocation check failed - token revoked",

        // Connector/Health errors (FCP-5xxx)
        "FCP-5001" => "Invalid sequence number",
        "FCP-5002" => "Timestamp skew too large",
        "FCP-5003" => "Unknown head reference",
        "FCP-5004" => "Invalid head reference",
        "FCP-5005" => "Not the coordinator for this zone",
        "FCP-5006" => "Invalid coordinator signature",
        "FCP-5007" => "Zone mismatch in checkpoint",
        "FCP-5008" => "Epoch mismatch",
        "FCP-5010" => "Fork detected in audit chain - manual intervention required",
        "FCP-5011" => "Connector unavailable",
        "FCP-5012" => "Connector not configured",
        "FCP-5013" => "Health check failed",

        // Resource errors (FCP-6xxx)
        "FCP-6001" => "Resource not found",
        "FCP-6002" => "Resource exhausted",
        "FCP-6003" => "Conflict - concurrent modification",
        "FCP-6004" => "Usage budget exceeded",

        // External service errors (FCP-7xxx)
        "FCP-7001" => "External service error",
        "FCP-7002" => "Upstream timeout",
        "FCP-7003" => "Dependency unavailable",

        // Internal errors (FCP-9xxx)
        "FCP-9001" => "Internal error",
        "FCP-9999" => "Unknown internal error",

        // Default for unrecognized codes
        _ => "Unknown reason code",
    }
}

/// Error when loading a decision receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainError {
    /// Error code (FCP-XXXX).
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Recovery hints for operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

impl ExplainError {
    /// Create a "receipt not found" error.
    #[must_use]
    pub fn receipt_not_found(request_id: &str) -> Self {
        Self {
            code: "FCP-6001".to_string(),
            message: format!("No DecisionReceipt found for request {request_id}"),
            hints: vec![
                "Verify the request object ID is correct".to_string(),
                "The receipt may not have been created yet (async processing)".to_string(),
                "Check if the zone is reachable and synchronized".to_string(),
            ],
        }
    }

    /// Create an "invalid object ID" error.
    #[must_use]
    pub fn invalid_object_id(id: &str, reason: &str) -> Self {
        Self {
            code: "FCP-1001".to_string(),
            message: format!("Invalid object ID '{id}': {reason}"),
            hints: vec![
                "Object IDs should be 64 hex characters (32 bytes)".to_string(),
                "Example: abc123...def456 (64 chars total)".to_string(),
            ],
        }
    }

    /// Create a "store unavailable" error.
    #[allow(dead_code)] // Planned for store integration
    #[must_use]
    pub fn store_unavailable(reason: &str) -> Self {
        Self {
            code: "FCP-5011".to_string(),
            message: format!("Object store unavailable: {reason}"),
            hints: vec![
                "Check network connectivity to mesh nodes".to_string(),
                "Run 'fcp doctor --zone <zone>' to diagnose".to_string(),
            ],
        }
    }

    /// Create a "receipt read failed" error.
    #[must_use]
    pub fn receipt_read_failed(path: &std::path::Path, reason: &str) -> Self {
        Self {
            code: "FCP-1001".to_string(),
            message: format!("Failed to read receipt at '{}': {reason}", path.display()),
            hints: vec![
                "Verify the receipt path exists and is readable".to_string(),
                "Ensure the file is not truncated or locked by another process".to_string(),
            ],
        }
    }

    /// Create an "invalid receipt format" error.
    #[must_use]
    pub fn receipt_decode_failed(path: &std::path::Path) -> Self {
        Self {
            code: "FCP-1002".to_string(),
            message: format!("Receipt at '{}' is not a supported format", path.display()),
            hints: vec![
                "Expected canonical CBOR DecisionReceipt/OperationReceipt".to_string(),
                "Or CBOR/JSON InvokeResponse or FcpErrorResponse".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn decision_outcome_symbols() {
        assert_eq!(DecisionOutcome::Allow.symbol(), "✓");
        assert_eq!(DecisionOutcome::Deny.symbol(), "✗");
    }

    #[test]
    fn evidence_type_labels() {
        assert_eq!(EvidenceType::CapabilityToken.label(), "Capability Token");
        assert_eq!(EvidenceType::Revocation.label(), "Revocation Entry");
        assert_eq!(EvidenceType::Unknown.label(), "Evidence Object");
    }

    #[test]
    fn reason_code_descriptions() {
        assert_eq!(
            reason_code_description("FCP-0000"),
            "Request allowed - all checks passed"
        );
        assert_eq!(
            reason_code_description("FCP-4030"),
            "Revocation check failed - token revoked"
        );
        assert_eq!(
            reason_code_description("FCP-5010"),
            "Fork detected in audit chain - manual intervention required"
        );
        assert_eq!(reason_code_description("FCP-XXXX"), "Unknown reason code");
    }

    #[test]
    fn explain_report_json_snapshot() {
        let generated_at = Utc.with_ymd_and_hms(2026, 1, 16, 12, 0, 0).unwrap();

        let report = ExplainReport {
            schema_version: "1.0.0".to_string(),
            generated_at,
            request_object_id: "request-id".to_string(),
            decision: DecisionOutcome::Deny,
            reason_code: "FCP-4030".to_string(),
            operation_id: Some("operation-id".to_string()),
            retry_after_ms: Some(5000),
            reason_description: "Revocation check failed - token revoked".to_string(),
            evidence: vec![
                EvidenceItem {
                    object_id: "evidence-capability".to_string(),
                    evidence_type: EvidenceType::CapabilityToken,
                    description: "Capability grant was revoked".to_string(),
                },
                EvidenceItem {
                    object_id: "evidence-revocation".to_string(),
                    evidence_type: EvidenceType::Revocation,
                    description: "Revocation entry recorded".to_string(),
                },
            ],
            explanation: Some("Demo revocation recorded".to_string()),
            zone_id: "z:work".to_string(),
            signed_by: SignerInfo {
                node_id: "node-demo".to_string(),
                signed_at: 1_700_000_000,
            },
        };

        let json = serde_json::to_string_pretty(&report).unwrap();

        // Verify key fields
        assert!(json.contains("\"schema_version\": \"1.0.0\""));
        assert!(json.contains("\"decision\": \"deny\""));
        assert!(json.contains("\"reason_code\": \"FCP-4030\""));
        assert!(json.contains("\"evidence_type\": \"capability_token\""));

        // Verify roundtrip
        let parsed: ExplainReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, DecisionOutcome::Deny);
        assert_eq!(parsed.reason_code, "FCP-4030");
        assert_eq!(parsed.evidence.len(), 2);
    }

    #[test]
    fn explain_error_receipt_not_found() {
        let err = ExplainError::receipt_not_found("abc123");
        assert_eq!(err.code, "FCP-6001");
        assert!(err.message.contains("abc123"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn explain_error_invalid_object_id() {
        let err = ExplainError::invalid_object_id("xyz", "too short");
        assert_eq!(err.code, "FCP-1001");
        assert!(err.message.contains("xyz"));
        assert!(err.message.contains("too short"));
    }

    // ── DecisionOutcome coverage ──

    #[test]
    fn decision_outcome_ansi_colors() {
        assert!(DecisionOutcome::Allow.ansi_color().contains("32")); // green
        assert!(DecisionOutcome::Deny.ansi_color().contains("31")); // red
    }

    #[test]
    fn decision_outcome_ansi_reset() {
        assert_eq!(DecisionOutcome::ansi_reset(), "\x1b[0m");
    }

    #[test]
    fn decision_outcome_serde_roundtrip() {
        for outcome in [DecisionOutcome::Allow, DecisionOutcome::Deny] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: DecisionOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, outcome);
        }
    }

    #[test]
    fn decision_outcome_serde_values() {
        assert_eq!(serde_json::to_string(&DecisionOutcome::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&DecisionOutcome::Deny).unwrap(), "\"deny\"");
    }

    #[test]
    fn decision_outcome_debug_clone_copy_eq() {
        let a = DecisionOutcome::Allow;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(a, DecisionOutcome::Deny);
        assert!(format!("{a:?}").contains("Allow"));
    }

    // ── EvidenceType coverage ──

    #[test]
    fn evidence_type_all_labels() {
        assert_eq!(EvidenceType::CapabilityToken.label(), "Capability Token");
        assert_eq!(EvidenceType::CapabilityGrant.label(), "Capability Grant");
        assert_eq!(EvidenceType::ZoneCheckpoint.label(), "Zone Checkpoint");
        assert_eq!(EvidenceType::Revocation.label(), "Revocation Entry");
        assert_eq!(EvidenceType::Policy.label(), "Policy Object");
        assert_eq!(EvidenceType::Approval.label(), "Approval Attestation");
        assert_eq!(EvidenceType::Request.label(), "Request Object");
        assert_eq!(EvidenceType::Unknown.label(), "Evidence Object");
    }

    #[test]
    fn evidence_type_serde_roundtrip() {
        let all_types = [
            EvidenceType::CapabilityToken,
            EvidenceType::CapabilityGrant,
            EvidenceType::ZoneCheckpoint,
            EvidenceType::Revocation,
            EvidenceType::Policy,
            EvidenceType::Approval,
            EvidenceType::Request,
            EvidenceType::Unknown,
        ];
        for et in all_types {
            let json = serde_json::to_string(&et).unwrap();
            let back: EvidenceType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, et);
        }
    }

    #[test]
    fn evidence_type_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&EvidenceType::CapabilityToken).unwrap(),
            "\"capability_token\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceType::ZoneCheckpoint).unwrap(),
            "\"zone_checkpoint\""
        );
    }

    #[test]
    fn evidence_type_debug_clone_copy_eq() {
        let a = EvidenceType::Policy;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, EvidenceType::Request);
        assert!(format!("{a:?}").contains("Policy"));
    }

    // ── EvidenceItem coverage ──

    #[test]
    fn evidence_item_serde_roundtrip() {
        let item = EvidenceItem {
            object_id: "abc123".into(),
            evidence_type: EvidenceType::Approval,
            description: "Admin approval".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: EvidenceItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.object_id, "abc123");
        assert_eq!(back.evidence_type, EvidenceType::Approval);
        assert_eq!(back.description, "Admin approval");
    }

    #[test]
    fn evidence_item_debug_clone() {
        let item = EvidenceItem {
            object_id: "x".into(),
            evidence_type: EvidenceType::Unknown,
            description: "test".into(),
        };
        let cloned = item.clone();
        assert_eq!(cloned.object_id, "x");
        assert!(format!("{item:?}").contains("EvidenceItem"));
    }

    // ── SignerInfo coverage ──

    #[test]
    fn signer_info_serde_roundtrip() {
        let info = SignerInfo {
            node_id: "node:test-123".into(),
            signed_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: SignerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.node_id, "node:test-123");
        assert_eq!(back.signed_at, 1_700_000_000);
    }

    #[test]
    fn signer_info_debug_clone() {
        let info = SignerInfo {
            node_id: "n".into(),
            signed_at: 0,
        };
        let cloned = info.clone();
        assert_eq!(cloned.signed_at, 0);
        assert!(format!("{info:?}").contains("SignerInfo"));
    }

    // ── ExplainReport additional coverage ──

    #[test]
    fn explain_report_schema_version_constant() {
        assert_eq!(ExplainReport::SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn explain_report_minimal_optional_fields() {
        let generated_at = Utc.with_ymd_and_hms(2026, 3, 4, 0, 0, 0).unwrap();
        let report = ExplainReport {
            schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
            generated_at,
            request_object_id: "req-1".into(),
            decision: DecisionOutcome::Allow,
            reason_code: "FCP-0000".into(),
            operation_id: None,
            retry_after_ms: None,
            reason_description: "all good".into(),
            evidence: vec![],
            explanation: None,
            zone_id: "z:test".into(),
            signed_by: SignerInfo {
                node_id: "node:a".into(),
                signed_at: 100,
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        // Optional None fields should be omitted
        assert!(!json.contains("operation_id"));
        assert!(!json.contains("retry_after_ms"));
        assert!(!json.contains("explanation"));
        // Roundtrip
        let back: ExplainReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision, DecisionOutcome::Allow);
        assert!(back.operation_id.is_none());
        assert!(back.evidence.is_empty());
    }

    #[test]
    fn explain_report_debug_clone() {
        let generated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let report = ExplainReport {
            schema_version: "1.0.0".into(),
            generated_at,
            request_object_id: "r".into(),
            decision: DecisionOutcome::Deny,
            reason_code: "FCP-9001".into(),
            operation_id: None,
            retry_after_ms: None,
            reason_description: "internal error".into(),
            evidence: vec![],
            explanation: None,
            zone_id: "z:x".into(),
            signed_by: SignerInfo { node_id: "n".into(), signed_at: 0 },
        };
        let cloned = report.clone();
        assert_eq!(cloned.reason_code, "FCP-9001");
        assert!(format!("{report:?}").contains("ExplainReport"));
    }

    // ── reason_code_description coverage ──

    #[test]
    fn reason_code_all_categories() {
        // Protocol errors
        assert!(reason_code_description("FCP-1001").contains("Invalid request"));
        assert!(reason_code_description("FCP-1002").contains("Malformed frame"));
        assert!(reason_code_description("FCP-1003").contains("Missing required"));
        assert!(reason_code_description("FCP-1004").contains("Checksum"));
        assert!(reason_code_description("FCP-1005").contains("Protocol version"));

        // Auth errors
        assert!(reason_code_description("FCP-2001").contains("Unauthorized"));
        assert!(reason_code_description("FCP-2002").contains("expired"));
        assert!(reason_code_description("FCP-2003").contains("Invalid signature"));
        assert!(reason_code_description("FCP-2004").contains("Principal"));

        // Capability errors
        assert!(reason_code_description("FCP-3001").contains("denied"));
        assert!(reason_code_description("FCP-3002").contains("Rate limited"));
        assert!(reason_code_description("FCP-3003").contains("not granted"));
        assert!(reason_code_description("FCP-3004").contains("not allowed"));
        assert!(reason_code_description("FCP-3005").contains("revoked"));

        // Zone/provenance errors
        assert!(reason_code_description("FCP-4001").contains("Zone violation"));
        assert!(reason_code_description("FCP-4002").contains("Taint violation"));
        assert!(reason_code_description("FCP-4010").contains("Provenance"));
        assert!(reason_code_description("FCP-4020").contains("Expired"));

        // Connector/health errors
        assert!(reason_code_description("FCP-5001").contains("sequence"));
        assert!(reason_code_description("FCP-5002").contains("skew"));
        assert!(reason_code_description("FCP-5003").contains("Unknown head"));
        assert!(reason_code_description("FCP-5004").contains("Invalid head"));
        assert!(reason_code_description("FCP-5005").contains("coordinator"));
        assert!(reason_code_description("FCP-5006").contains("coordinator signature"));
        assert!(reason_code_description("FCP-5007").contains("Zone mismatch"));
        assert!(reason_code_description("FCP-5008").contains("Epoch"));
        assert!(reason_code_description("FCP-5011").contains("unavailable"));
        assert!(reason_code_description("FCP-5012").contains("not configured"));
        assert!(reason_code_description("FCP-5013").contains("Health check"));

        // Resource errors
        assert!(reason_code_description("FCP-6001").contains("not found"));
        assert!(reason_code_description("FCP-6002").contains("exhausted"));
        assert!(reason_code_description("FCP-6003").contains("Conflict"));
        assert!(reason_code_description("FCP-6004").contains("budget"));

        // External errors
        assert!(reason_code_description("FCP-7001").contains("External"));
        assert!(reason_code_description("FCP-7002").contains("timeout"));
        assert!(reason_code_description("FCP-7003").contains("unavailable"));

        // Internal errors
        assert!(reason_code_description("FCP-9001").contains("Internal"));
        assert!(reason_code_description("FCP-9999").contains("Unknown internal"));
    }

    // ── ExplainError additional constructors ──

    #[test]
    fn explain_error_store_unavailable() {
        let err = ExplainError::store_unavailable("disk full");
        assert_eq!(err.code, "FCP-5011");
        assert!(err.message.contains("disk full"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn explain_error_receipt_read_failed() {
        let path = std::path::Path::new("/tmp/receipt.cbor");
        let err = ExplainError::receipt_read_failed(path, "permission denied");
        assert_eq!(err.code, "FCP-1001");
        assert!(err.message.contains("/tmp/receipt.cbor"));
        assert!(err.message.contains("permission denied"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn explain_error_receipt_decode_failed() {
        let path = std::path::Path::new("/tmp/bad.bin");
        let err = ExplainError::receipt_decode_failed(path);
        assert_eq!(err.code, "FCP-1002");
        assert!(err.message.contains("/tmp/bad.bin"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn explain_error_serde_roundtrip() {
        let err = ExplainError::receipt_not_found("req-42");
        let json = serde_json::to_string(&err).unwrap();
        let back: ExplainError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, "FCP-6001");
        assert!(back.message.contains("req-42"));
        assert_eq!(back.hints.len(), err.hints.len());
    }

    #[test]
    fn explain_error_empty_hints_omitted() {
        let err = ExplainError {
            code: "FCP-0000".into(),
            message: "test".into(),
            hints: vec![],
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("hints"));
    }

    #[test]
    fn explain_error_debug_clone() {
        let err = ExplainError::invalid_object_id("bad", "reason");
        let cloned = err.clone();
        assert_eq!(cloned.code, err.code);
        assert!(format!("{err:?}").contains("ExplainError"));
    }
}
