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
}
