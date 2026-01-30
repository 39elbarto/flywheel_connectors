//! `fcp explain` command implementation.
//!
//! Renders the mechanical evidence behind an allow/deny decision by loading
//! and displaying the `DecisionReceipt` for a given request object ID.
//!
//! # Usage
//!
//! ```text
//! # Human-readable output
//! fcp explain --request <object-id>
//! fcp explain --receipt <path>
//!
//! # JSON output for tooling
//! fcp explain --request <object-id> --json
//! fcp explain --receipt <path> --output <file>
//! ```

pub mod types;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args;
use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_core::{DecisionReceipt, FcpErrorResponse, InvokeResponse, InvokeStatus, OperationReceipt};
use semver::Version;
use serde::de::DeserializeOwned;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use types::{
    DecisionOutcome, EvidenceItem, EvidenceType, ExplainError, ExplainReport, SignerInfo,
    reason_code_description,
};

/// Arguments for the `fcp explain` command.
#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// Request object ID to explain (hex-encoded, 64 characters).
    #[arg(
        long,
        short = 'r',
        conflicts_with = "receipt",
        required_unless_present = "receipt"
    )]
    pub request: Option<String>,

    /// Receipt file to explain (DecisionReceipt/OperationReceipt/InvokeResponse).
    #[arg(long, conflicts_with = "request")]
    pub receipt: Option<PathBuf>,

    /// Output JSON to a file (implies --json).
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Zone to query (defaults to local zone).
    #[arg(long, short = 'z')]
    pub zone: Option<String>,
}

/// Run the explain command.
///
/// # Errors
///
/// Returns an error if the decision receipt cannot be loaded or rendered.
pub fn run(args: &ExplainArgs) -> Result<()> {
    if let Some(receipt_path) = args.receipt.as_deref() {
        match load_receipt_from_file(receipt_path) {
            Ok(report) => output_report(&report, args.json, args.output.as_deref()),
            Err(error) => output_error(&error, args.json, args.output.as_deref()),
        }
    } else {
        let request = args
            .request
            .as_deref()
            .expect("request required unless receipt provided");

        // Validate object ID format
        if let Err(e) = validate_object_id(request) {
            let error = ExplainError::invalid_object_id(request, &e);
            return output_error(&error, args.json, args.output.as_deref());
        }

        // TODO: In a full implementation, this would load the DecisionReceipt from
        // the object store. For now, we demonstrate the output format with a
        // simulated lookup that returns "not found" or a demo receipt.
        //
        // Full implementation would:
        // 1. Connect to the mesh node for the specified zone
        // 2. Query the object store for a DecisionReceipt with request_object_id == args.request
        // 3. If found, render it; if not found, return ExplainError::receipt_not_found

        // For demonstration, check if this is a known test object ID
        match load_decision_receipt(request, args.zone.as_deref()) {
            Ok(report) => output_report(&report, args.json, args.output.as_deref()),
            Err(error) => output_error(&error, args.json, args.output.as_deref()),
        }
    }
}

/// Validate an object ID string.
fn validate_object_id(id: &str) -> Result<(), String> {
    // Object IDs are 32 bytes = 64 hex characters
    if id.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", id.len()));
    }

    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("contains non-hexadecimal characters".to_string());
    }

    Ok(())
}

/// Load a decision receipt (stub implementation).
///
/// In a full implementation, this would query the object store.
fn load_decision_receipt(
    request_id: &str,
    _zone: Option<&str>,
) -> Result<ExplainReport, ExplainError> {
    // Stub: Return demo data for specific test IDs, otherwise "not found"
    //
    // Test IDs for demonstration:
    // - "0000...0001" (64 chars with trailing 1) -> Allow receipt
    // - "0000...0002" (64 chars with trailing 2) -> Deny receipt (revoked)
    // - "0000...0003" (64 chars with trailing 3) -> Deny receipt (zone violation)
    // - anything else -> not found

    let suffix = &request_id[60..]; // Last 4 chars

    match suffix {
        "0001" => Ok(create_demo_allow_receipt(request_id)),
        "0002" => Ok(create_demo_deny_revoked_receipt(request_id)),
        "0003" => Ok(create_demo_deny_zone_violation_receipt(request_id)),
        _ => Err(ExplainError::receipt_not_found(request_id)),
    }
}

fn load_receipt_from_file(path: &Path) -> Result<ExplainReport, ExplainError> {
    let bytes =
        fs::read(path).map_err(|err| ExplainError::receipt_read_failed(path, &err.to_string()))?;

    let decision_schema = SchemaId::new("fcp.core", "DecisionReceipt", Version::new(1, 0, 0));
    if let Ok(receipt) =
        CanonicalSerializer::deserialize::<DecisionReceipt>(&bytes, &decision_schema)
    {
        return Ok(report_from_decision_receipt(&receipt));
    }

    let operation_schema = SchemaId::new("fcp.core", "OperationReceipt", Version::new(1, 0, 0));
    if let Ok(receipt) =
        CanonicalSerializer::deserialize::<OperationReceipt>(&bytes, &operation_schema)
    {
        return Ok(report_from_operation_receipt(&receipt));
    }

    if let Some(receipt) = try_decode_cbor::<DecisionReceipt>(&bytes) {
        return Ok(report_from_decision_receipt(&receipt));
    }

    if let Some(receipt) = try_decode_cbor::<OperationReceipt>(&bytes) {
        return Ok(report_from_operation_receipt(&receipt));
    }

    if let Some(response) = try_decode_cbor::<InvokeResponse>(&bytes) {
        return Ok(report_from_invoke_response(&response));
    }

    if let Some(response) = try_decode_cbor::<FcpErrorResponse>(&bytes) {
        return Ok(report_from_error_response(response, None));
    }

    if let Ok(response) = serde_json::from_slice::<InvokeResponse>(&bytes) {
        return Ok(report_from_invoke_response(&response));
    }

    if let Ok(response) = serde_json::from_slice::<FcpErrorResponse>(&bytes) {
        return Ok(report_from_error_response(response, None));
    }

    Err(ExplainError::receipt_decode_failed(path))
}

fn try_decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let mut cursor = Cursor::new(bytes);
    ciborium::de::from_reader(&mut cursor).ok()
}

fn report_from_decision_receipt(receipt: &DecisionReceipt) -> ExplainReport {
    let retry_after_ms = if receipt.reason_code == "FCP-3002" {
        Some(0)
    } else {
        None
    };
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: receipt.request_object_id.to_string(),
        decision: match receipt.decision {
            fcp_core::Decision::Allow => DecisionOutcome::Allow,
            fcp_core::Decision::Deny => DecisionOutcome::Deny,
        },
        reason_code: receipt.reason_code.clone(),
        operation_id: None,
        retry_after_ms,
        reason_description: reason_code_description(&receipt.reason_code).to_string(),
        evidence: receipt
            .evidence
            .iter()
            .map(|object_id| EvidenceItem {
                object_id: object_id.to_string(),
                evidence_type: EvidenceType::Unknown,
                description: format!("Evidence object {}", truncate_id(&object_id.to_string())),
            })
            .collect(),
        explanation: receipt.explanation.clone(),
        zone_id: receipt.header.zone_id.to_string(),
        signed_by: SignerInfo {
            node_id: receipt.signature.node_id.to_string(),
            signed_at: receipt.signature.signed_at,
        },
    }
}

fn report_from_operation_receipt(receipt: &OperationReceipt) -> ExplainReport {
    let request_id = receipt.request_object_id.to_string();
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.clone(),
        decision: DecisionOutcome::Allow,
        reason_code: "FCP-0000".to_string(),
        // Operation ID is not encoded in the receipt; fall back to request id so
        // E2E scripts have a stable non-empty identifier.
        operation_id: Some(request_id),
        retry_after_ms: None,
        reason_description: reason_code_description("FCP-0000").to_string(),
        evidence: Vec::new(),
        explanation: None,
        zone_id: receipt.header.zone_id.to_string(),
        signed_by: SignerInfo {
            node_id: receipt.signature.node_id.to_string(),
            signed_at: receipt.signature.signed_at,
        },
    }
}

fn report_from_invoke_response(response: &InvokeResponse) -> ExplainReport {
    let request_id = response.id.to_string();
    match response.status {
        InvokeStatus::Ok => ExplainReport {
            schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            request_object_id: request_id.clone(),
            decision: DecisionOutcome::Allow,
            reason_code: "FCP-0000".to_string(),
            operation_id: Some(request_id),
            retry_after_ms: None,
            reason_description: reason_code_description("FCP-0000").to_string(),
            evidence: Vec::new(),
            explanation: None,
            zone_id: "unknown".to_string(),
            signed_by: SignerInfo {
                node_id: "unknown".to_string(),
                signed_at: 0,
            },
        },
        InvokeStatus::Error => response.error.as_ref().map_or_else(
            || {
                report_from_error_response(
                    FcpErrorResponse {
                        code: "FCP-9001".to_string(),
                        message: "invoke failed without error payload".to_string(),
                        retryable: false,
                        retry_after_ms: None,
                        details: None,
                        ai_recovery_hint: None,
                    },
                    Some(request_id.clone()),
                )
            },
            |err| report_from_error_response(err.to_response(), Some(request_id.clone())),
        ),
    }
}

fn report_from_error_response(
    response: FcpErrorResponse,
    request_id: Option<String>,
) -> ExplainReport {
    let request_id = request_id.unwrap_or_else(|| "unknown".to_string());
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.clone(),
        decision: DecisionOutcome::Deny,
        reason_code: response.code.clone(),
        operation_id: Some(request_id),
        retry_after_ms: response.retry_after_ms,
        reason_description: reason_code_description(&response.code).to_string(),
        evidence: Vec::new(),
        explanation: Some(response.message),
        zone_id: "unknown".to_string(),
        signed_by: SignerInfo {
            node_id: "unknown".to_string(),
            signed_at: 0,
        },
    }
}

fn create_demo_allow_receipt(request_id: &str) -> ExplainReport {
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.to_string(),
        decision: DecisionOutcome::Allow,
        reason_code: "FCP-0000".to_string(),
        operation_id: Some(request_id.to_string()),
        retry_after_ms: None,
        reason_description: reason_code_description("FCP-0000").to_string(),
        evidence: vec![
            EvidenceItem {
                object_id: "a".repeat(64),
                evidence_type: EvidenceType::CapabilityToken,
                description: "Valid capability token with required permissions".to_string(),
            },
            EvidenceItem {
                object_id: "b".repeat(64),
                evidence_type: EvidenceType::ZoneCheckpoint,
                description: "Current zone checkpoint (seq=42)".to_string(),
            },
        ],
        explanation: None,
        zone_id: "z:work".to_string(),
        signed_by: SignerInfo {
            node_id: "node-mesh-1".to_string(),
            signed_at: current_timestamp(),
        },
    }
}

/// Get the current Unix timestamp.
#[allow(clippy::cast_sign_loss)] // Timestamps after 1970 are positive
fn current_timestamp() -> u64 {
    Utc::now().timestamp() as u64
}

fn create_demo_deny_revoked_receipt(request_id: &str) -> ExplainReport {
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.to_string(),
        decision: DecisionOutcome::Deny,
        reason_code: "FCP-4030".to_string(),
        operation_id: None,
        retry_after_ms: None,
        reason_description: reason_code_description("FCP-4030").to_string(),
        evidence: vec![
            EvidenceItem {
                object_id: "c".repeat(64),
                evidence_type: EvidenceType::CapabilityToken,
                description: "Capability token (jti: <redacted>)".to_string(),
            },
            EvidenceItem {
                object_id: "d".repeat(64),
                evidence_type: EvidenceType::Revocation,
                description: "Revocation entry added at epoch 37".to_string(),
            },
        ],
        explanation: Some(
            "Token was revoked by zone administrator due to credential rotation".to_string(),
        ),
        zone_id: "z:work".to_string(),
        signed_by: SignerInfo {
            node_id: "node-mesh-1".to_string(),
            signed_at: current_timestamp(),
        },
    }
}

fn create_demo_deny_zone_violation_receipt(request_id: &str) -> ExplainReport {
    ExplainReport {
        schema_version: ExplainReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        request_object_id: request_id.to_string(),
        decision: DecisionOutcome::Deny,
        reason_code: "FCP-4001".to_string(),
        operation_id: None,
        retry_after_ms: None,
        reason_description: reason_code_description("FCP-4001").to_string(),
        evidence: vec![
            EvidenceItem {
                object_id: "e".repeat(64),
                evidence_type: EvidenceType::Request,
                description: "Request originated from zone z:external".to_string(),
            },
            EvidenceItem {
                object_id: "f".repeat(64),
                evidence_type: EvidenceType::Policy,
                description: "Zone policy denies access from z:external to z:sensitive".to_string(),
            },
        ],
        explanation: Some(
            "Cross-zone access denied: z:external cannot invoke operations in z:sensitive"
                .to_string(),
        ),
        zone_id: "z:sensitive".to_string(),
        signed_by: SignerInfo {
            node_id: "node-mesh-2".to_string(),
            signed_at: current_timestamp(),
        },
    }
}

/// Output the explain report.
fn output_report(report: &ExplainReport, json: bool, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        let file = fs::File::create(path)
            .with_context(|| format!("failed to create output file {}", path.display()))?;
        serde_json::to_writer_pretty(file, report).context("failed to serialize report to JSON")?;
        return Ok(());
    }

    if json {
        let output =
            serde_json::to_string_pretty(report).context("failed to serialize report to JSON")?;
        println!("{output}");
    } else {
        print_human_readable(report);
    }
    Ok(())
}

/// Output an error.
fn output_error(error: &ExplainError, json: bool, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        let file = fs::File::create(path)
            .with_context(|| format!("failed to create output file {}", path.display()))?;
        serde_json::to_writer_pretty(file, error).context("failed to serialize error to JSON")?;
        return Ok(());
    }

    if json {
        let output =
            serde_json::to_string_pretty(error).context("failed to serialize error to JSON")?;
        println!("{output}");
        // Return Ok since we successfully output the error as JSON
        // (this allows scripting to parse the error)
        Ok(())
    } else {
        print_human_error(error);
        // Return an error for non-JSON mode to signal failure to callers
        anyhow::bail!("{}: {}", error.code, error.message)
    }
}

/// Print human-readable report to stdout.
fn print_human_readable(report: &ExplainReport) {
    let reset = DecisionOutcome::ansi_reset();

    // Header
    println!();
    println!("Decision Explanation");
    println!("====================");
    println!();

    // Decision with color
    let color = report.decision.ansi_color();
    let symbol = report.decision.symbol();
    let decision_str = match report.decision {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
    };
    println!("Decision:     {color}{symbol} {decision_str}{reset}");
    println!("Reason Code:  {}", report.reason_code);
    println!("Reason:       {}", report.reason_description);
    println!();

    // Request info
    println!("Request:      {}", truncate_id(&report.request_object_id));
    println!("Zone:         {}", report.zone_id);
    println!();

    // Explanation (if present)
    if let Some(ref explanation) = report.explanation {
        println!("Explanation:");
        for line in textwrap::wrap(explanation, 70) {
            println!("  {line}");
        }
        println!();
    }

    // Evidence
    if !report.evidence.is_empty() {
        println!("Evidence ({} items):", report.evidence.len());
        println!();
        for (i, item) in report.evidence.iter().enumerate() {
            println!(
                "  {}. {} ({})",
                i + 1,
                item.evidence_type.label(),
                truncate_id(&item.object_id)
            );
            println!("     {}", item.description);
        }
        println!();
    }

    // Signature info
    #[allow(clippy::cast_possible_wrap)] // Timestamps fit in i64 until year 292 billion
    let signed_at_i64 = report.signed_by.signed_at as i64;
    let signed_at_str = chrono::DateTime::from_timestamp(signed_at_i64, 0).map_or_else(
        || report.signed_by.signed_at.to_string(),
        |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );
    println!(
        "Signed by:    {} at {}",
        report.signed_by.node_id, signed_at_str
    );
    println!();
}

/// Print human-readable error to stderr.
fn print_human_error(error: &ExplainError) {
    eprintln!();
    eprintln!("\x1b[31mError: {}\x1b[0m", error.code);
    eprintln!("{}", error.message);

    if !error.hints.is_empty() {
        eprintln!();
        eprintln!("Hints:");
        for hint in &error.hints {
            eprintln!("  - {hint}");
        }
    }
    eprintln!();
}

/// Truncate a hex ID for display (show first 8 and last 8 chars).
fn truncate_id(id: &str) -> String {
    if id.len() <= 20 {
        id.to_string()
    } else {
        format!("{}...{}", &id[..8], &id[id.len() - 8..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_object_id_valid() {
        let valid_id = "a".repeat(64);
        assert!(validate_object_id(&valid_id).is_ok());
    }

    #[test]
    fn validate_object_id_too_short() {
        let short_id = "abc123";
        let result = validate_object_id(short_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 64"));
    }

    #[test]
    fn validate_object_id_non_hex() {
        let bad_id = "g".repeat(64); // 'g' is not hex
        let result = validate_object_id(&bad_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-hexadecimal"));
    }

    #[test]
    fn truncate_id_short() {
        assert_eq!(truncate_id("abc123"), "abc123");
    }

    #[test]
    fn truncate_id_long() {
        let long_id = "a".repeat(64);
        let truncated = truncate_id(&long_id);
        assert_eq!(truncated, "aaaaaaaa...aaaaaaaa");
    }

    #[test]
    fn load_demo_allow_receipt() {
        let request_id = format!("{}0001", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.decision, DecisionOutcome::Allow);
        assert_eq!(report.reason_code, "FCP-0000");
    }

    #[test]
    fn load_demo_deny_revoked_receipt() {
        let request_id = format!("{}0002", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.decision, DecisionOutcome::Deny);
        assert_eq!(report.reason_code, "FCP-4030");
    }

    #[test]
    fn load_demo_deny_zone_violation_receipt() {
        let request_id = format!("{}0003", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.decision, DecisionOutcome::Deny);
        assert_eq!(report.reason_code, "FCP-4001");
    }

    #[test]
    fn load_receipt_not_found() {
        let request_id = format!("{}9999", "0".repeat(60));
        let result = load_decision_receipt(&request_id, None);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, "FCP-6001");
    }
}
