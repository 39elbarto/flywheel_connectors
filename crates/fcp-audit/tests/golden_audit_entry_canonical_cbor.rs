//! Frozen-byte golden tests for fcp-audit canonical CBOR encoding.
//!
//! AmberLark, 2026-05-02 — testing-golden-artifacts alpha-domain sweep.
//!
//! Companion to `golden_receipts.rs` (which pins JSON snapshots of
//! `AuditEntry` / `ChainHead` / `DecisionReceipt`). This file pins
//! the CBOR-CANONICAL byte layout — the wire form that crosses
//! mesh peers and gets signed via `AuditEntry::signing_bytes`. JSON
//! snapshots catch field renames; CBOR snapshots catch field
//! re-ordering and integer-encoding drift that JSON masks.
//!
//! Severity-matrix coverage: pins one entry per `Severity` variant
//! so adding/removing a variant or changing the lowercase-snake_case
//! serde tag is caught at test time.
//!
//! When you intentionally change the schema:
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-audit
//!     cargo insta review        # human reviews every diff
//!     git add crates/fcp-audit/tests/snapshots/
//!
//! Any other change MUST fail these tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fcp_audit::{AuditEntry, Severity, TraceContext};
use fcp_cbor::to_canonical_cbor;
use serde_json::json;

/// Render bytes as a hex dump with section labels for human review.
fn dump(label: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(label);
    out.push('\n');
    writeln!(&mut out, "len = {}", bytes.len()).expect("writing to String cannot fail");
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(&mut out, "{:04x}  {:48}  {}", i * 16, hex, ascii)
            .expect("writing to String cannot fail");
    }
    out
}

/// Build a deterministic AuditEntry shell. Mutate severity per-test
/// to exercise the variant matrix without re-stating every field.
fn fixture_audit_entry_with_severity(severity: Severity, id_suffix: &str) -> AuditEntry {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "fixture_label".to_string(),
        json!("golden_audit_entry_canonical_cbor"),
    );
    metadata.insert("severity_label".to_string(), json!(format!("{severity}")));

    AuditEntry {
        id: format!("audit-fixture-{id_suffix}"),
        event_type: "capability.invoke".to_string(),
        severity,
        actor: "user:golden-fixture".to_string(),
        zone_id: "z:work".to_string(),
        seq: 42,
        occurred_at: 1_700_000_000,
        prev: Some("audit-fixture-prev".to_string()),
        correlation_id: "corr-golden-fixture".to_string(),
        trace_context: Some(TraceContext::new(
            "trace-id-golden-fixture",
            "span-id-golden-fixture",
        )),
        connector_id: Some("fcp.golden:utility:1.0.0".to_string()),
        operation_id: Some("op.golden.invoke".to_string()),
        metadata,
        issuer_kid: None,
        signature: None,
    }
}

#[test]
fn audit_entry_canonical_cbor_severity_info() {
    let entry = fixture_audit_entry_with_severity(Severity::Info, "info");
    let bytes = to_canonical_cbor(&entry).expect("info entry encodes");
    insta::assert_snapshot!(dump(
        "AuditEntry (Severity::Info, full fixture) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn audit_entry_canonical_cbor_severity_warning() {
    let entry = fixture_audit_entry_with_severity(Severity::Warning, "warning");
    let bytes = to_canonical_cbor(&entry).expect("warning entry encodes");
    insta::assert_snapshot!(dump(
        "AuditEntry (Severity::Warning, full fixture) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn audit_entry_canonical_cbor_severity_error() {
    let entry = fixture_audit_entry_with_severity(Severity::Error, "error");
    let bytes = to_canonical_cbor(&entry).expect("error entry encodes");
    insta::assert_snapshot!(dump(
        "AuditEntry (Severity::Error, full fixture) canonical CBOR",
        &bytes,
    ));
}

#[test]
fn audit_entry_canonical_cbor_severity_critical() {
    let entry = fixture_audit_entry_with_severity(Severity::Critical, "critical");
    let bytes = to_canonical_cbor(&entry).expect("critical entry encodes");
    insta::assert_snapshot!(dump(
        "AuditEntry (Severity::Critical, full fixture) canonical CBOR",
        &bytes,
    ));
}

/// Pin the signing-transcript bytes for a fully-populated AuditEntry.
/// `signing_bytes()` is what gets fed to `Ed25519::sign` — a refactor
/// that reordered fields here would invalidate every existing audit
/// signature in the workspace without breaking any round-trip serde
/// test.
#[test]
fn audit_entry_signing_bytes_layout_full_fixture() {
    let entry = fixture_audit_entry_with_severity(Severity::Critical, "signing-transcript");
    let bytes = entry
        .signing_bytes()
        .expect("AuditEntry::signing_bytes encodes for fixture");
    insta::assert_snapshot!(dump(
        "AuditEntry::signing_bytes (Critical fixture, all fields populated)",
        &bytes,
    ));
}
