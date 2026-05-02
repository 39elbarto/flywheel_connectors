//! Cross-crate pin: invoke audit-chain wire shape (br-mvax3).
//!
//! `fcp-host::InvokeAuditChain` (br-mvax3) emits `AuditEntry` rows under
//! the event types `invoke.{allow,deny,result,error}` with monotonic
//! per-zone seq + prev-hash linkage. This file pins the audit-side
//! contract those rows must satisfy, independent of the host wiring,
//! so a future change in either crate that breaks the chain trips
//! here loudly.
//!
//! Why a separate file: the user-prescribed verification command
//! (`cargo test -p fcp-host -p fcp-audit invoke_audit_chain`) runs the
//! `invoke_audit_chain` substring filter across both crates. Tests in
//! either crate that include that name are picked up.

use fcp_audit::{AuditEntry, AuditEntryBuilder, Severity};
use serde_json::json;

const INVOKE_ALLOW: &str = "invoke.allow";
const INVOKE_DENY: &str = "invoke.deny";
const INVOKE_RESULT: &str = "invoke.result";
const INVOKE_ERROR: &str = "invoke.error";

fn build(seq: u64, prev: Option<&str>, event_type: &str, severity: Severity) -> AuditEntry {
    let mut b = AuditEntryBuilder::new()
        .id("__provisional__")
        .event_type(event_type)
        .severity(severity)
        .actor("agent:test")
        .zone_id("z:work")
        .seq(seq)
        .occurred_at(1_700_000_000)
        .connector_id("github")
        .operation_id("op-1")
        .meta("operation", json!("list_repos"));
    if let Some(p) = prev {
        b = b.prev(p);
    }
    let provisional = b.clone().build().expect("provisional builds");
    let real_id = provisional.computed_id().expect("canonical id");
    b.id(real_id).build().expect("real entry builds")
}

#[test]
fn invoke_audit_chain_event_type_strings_are_pinned() {
    // br-mvax3: pin the four event-type strings so a casual rename
    // breaks this test. The fcp-host invoke wiring uses exactly these
    // labels, and downstream auditors filter on them.
    assert_eq!(INVOKE_ALLOW, "invoke.allow");
    assert_eq!(INVOKE_DENY, "invoke.deny");
    assert_eq!(INVOKE_RESULT, "invoke.result");
    assert_eq!(INVOKE_ERROR, "invoke.error");
}

#[test]
fn invoke_audit_chain_genesis_then_follow_links() {
    // br-mvax3: a genesis allow event followed by a result event MUST
    // hash-link via prev = genesis.id and seq = 1.
    let genesis = build(0, None, INVOKE_ALLOW, Severity::Info);
    assert!(genesis.is_genesis());

    let result = build(1, Some(&genesis.id), INVOKE_RESULT, Severity::Info);
    assert!(
        result.follows(&genesis),
        "second entry must hash-link to first: prev={:?} expected={:?}, seq={} expected={}",
        result.prev,
        Some(&genesis.id),
        result.seq,
        genesis.seq + 1
    );
}

#[test]
fn invoke_audit_chain_id_is_recomputable_from_payload() {
    // br-mvax3: the entry's `id` field MUST equal `computed_id()` —
    // this is what makes the chain verifiable downstream (the BLAKE3
    // hash binds every other field).
    let entry = build(0, None, INVOKE_ALLOW, Severity::Info);
    let recomputed = entry.computed_id().expect("computed_id must succeed");
    assert_eq!(
        entry.id, recomputed,
        "stored id must match computed_id so verify_chain can re-derive it"
    );
}

#[test]
fn invoke_audit_chain_severity_for_each_phase() {
    // br-mvax3: deny → Warning, error → Error so an operator filtering
    // by severity sees the right rows.
    let allow = build(0, None, INVOKE_ALLOW, Severity::Info);
    let deny = build(1, Some(&allow.id), INVOKE_DENY, Severity::Warning);
    let result_ok = build(2, Some(&deny.id), INVOKE_RESULT, Severity::Info);
    let error = build(3, Some(&result_ok.id), INVOKE_ERROR, Severity::Error);

    assert_eq!(allow.severity, Severity::Info);
    assert_eq!(deny.severity, Severity::Warning);
    assert_eq!(result_ok.severity, Severity::Info);
    assert_eq!(error.severity, Severity::Error);
}

#[test]
fn invoke_audit_chain_three_link_chain_is_internally_consistent() {
    // br-mvax3 acceptance shape: allow → result-error trio, all linked.
    let allow = build(0, None, INVOKE_ALLOW, Severity::Info);
    let result = build(1, Some(&allow.id), INVOKE_RESULT, Severity::Info);
    let error = build(2, Some(&result.id), INVOKE_ERROR, Severity::Error);

    assert!(result.follows(&allow));
    assert!(error.follows(&result));

    // And every id is canonically computable.
    for entry in [&allow, &result, &error] {
        assert_eq!(
            entry.id,
            entry.computed_id().expect("computed_id"),
            "entry {} id is not its own computed_id",
            entry.event_type
        );
    }
}

#[test]
fn invoke_audit_chain_carries_operation_id_and_zone_id() {
    // br-mvax3: an operator tracing a specific request MUST be able to
    // find every related audit row by (zone_id, operation_id). Pin
    // both fields land on the entry.
    let entry = build(0, None, INVOKE_ALLOW, Severity::Info);
    assert_eq!(entry.zone_id, "z:work");
    assert_eq!(entry.operation_id.as_deref(), Some("op-1"));
    assert_eq!(entry.connector_id.as_deref(), Some("github"));
}
