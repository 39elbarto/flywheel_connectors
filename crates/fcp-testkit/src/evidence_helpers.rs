//! Evidence and artifact assertion helpers.
//!
//! Provides utilities for testing that connectors produce the expected
//! evidence artifacts: audit events, operation receipts, decision records,
//! and structured log traces.
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::evidence_helpers::*;
//!
//! let mut collector = EvidenceCollector::new();
//! collector.record_audit_event("invoke", "gmail.search", json!({"zone": "z:private"}));
//! collector.record_receipt("req_1", "op_1", true);
//!
//! assert_evidence_has_audit_event(&collector, "invoke");
//! assert_evidence_has_receipt(&collector, "req_1");
//! assert_evidence_no_secrets(&collector, &["sk-test-", "Bearer "]);
//! ```

use crate::database_helpers::{
    CleanupVerificationResult, FixtureMutationRecord, FixtureSeedRecord,
};
use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────────
// Evidence Collector
// ─────────────────────────────────────────────────────────────────────────────

/// Collects evidence artifacts during connector test execution.
#[derive(Debug, Default)]
pub struct EvidenceCollector {
    /// Recorded audit events.
    pub audit_events: Vec<AuditEvidence>,
    /// Recorded operation receipts.
    pub receipts: Vec<ReceiptEvidence>,
    /// Recorded decision records (approval/denial).
    pub decisions: Vec<DecisionEvidence>,
    /// Recorded structured log lines.
    pub log_lines: Vec<Value>,
    /// Recorded seeded state for truthful local fixture runs.
    pub seeded_state: Vec<FixtureSeedRecord>,
    /// Recorded state mutations exercised during the run.
    pub mutations: Vec<FixtureMutationRecord>,
    /// Recorded cleanup verification results from teardown.
    pub cleanup_verifications: Vec<CleanupVerificationResult>,
}

/// A recorded audit event.
#[derive(Debug, Clone)]
pub struct AuditEvidence {
    /// Event type (e.g., "invoke", "configure", "health").
    pub event_type: String,
    /// Operation that produced this event.
    pub operation: String,
    /// Additional context.
    pub context: Value,
    /// Whether this event was zone-scoped.
    pub zone_scoped: bool,
}

/// A recorded operation receipt.
#[derive(Debug, Clone)]
pub struct ReceiptEvidence {
    /// Request ID that produced this receipt.
    pub request_id: String,
    /// Operation ID.
    pub operation_id: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Idempotency key if present.
    pub idempotency_key: Option<String>,
}

/// A recorded decision (approval or denial).
#[derive(Debug, Clone)]
pub struct DecisionEvidence {
    /// What was decided on.
    pub subject: String,
    /// Whether it was approved.
    pub approved: bool,
    /// Reason for the decision.
    pub reason: String,
}

impl EvidenceCollector {
    /// Create a new empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an audit event.
    pub fn record_audit_event(&mut self, event_type: &str, operation: &str, context: Value) {
        self.audit_events.push(AuditEvidence {
            event_type: event_type.to_string(),
            operation: operation.to_string(),
            context,
            zone_scoped: true,
        });
    }

    /// Record an audit event without zone scoping.
    pub fn record_unscoped_audit_event(
        &mut self,
        event_type: &str,
        operation: &str,
        context: Value,
    ) {
        self.audit_events.push(AuditEvidence {
            event_type: event_type.to_string(),
            operation: operation.to_string(),
            context,
            zone_scoped: false,
        });
    }

    /// Record an operation receipt.
    pub fn record_receipt(&mut self, request_id: &str, operation_id: &str, success: bool) {
        self.receipts.push(ReceiptEvidence {
            request_id: request_id.to_string(),
            operation_id: operation_id.to_string(),
            success,
            idempotency_key: None,
        });
    }

    /// Record a receipt with idempotency key.
    pub fn record_receipt_with_key(
        &mut self,
        request_id: &str,
        operation_id: &str,
        success: bool,
        key: &str,
    ) {
        self.receipts.push(ReceiptEvidence {
            request_id: request_id.to_string(),
            operation_id: operation_id.to_string(),
            success,
            idempotency_key: Some(key.to_string()),
        });
    }

    /// Record an approval or denial decision.
    pub fn record_decision(&mut self, subject: &str, approved: bool, reason: &str) {
        self.decisions.push(DecisionEvidence {
            subject: subject.to_string(),
            approved,
            reason: reason.to_string(),
        });
    }

    /// Record a structured log line.
    pub fn record_log_line(&mut self, line: Value) {
        self.log_lines.push(line);
    }

    /// Record seeded state for a truthful local fixture.
    pub fn record_seeded_state(&mut self, resource: &str, identifier: &str, payload: Value) {
        self.seeded_state
            .push(FixtureSeedRecord::new(resource, identifier, payload));
    }

    /// Record a state mutation exercised during the run.
    pub fn record_mutation(&mut self, mutation: FixtureMutationRecord) {
        self.mutations.push(mutation);
    }

    /// Record a cleanup verification result from teardown.
    pub fn record_cleanup_verification(
        &mut self,
        check_id: &str,
        resource: &str,
        method: &str,
        expected_state: &str,
        observed: Value,
        passed: bool,
    ) {
        self.cleanup_verifications
            .push(CleanupVerificationResult::new(
                check_id,
                resource,
                method,
                expected_state,
                observed,
                passed,
            ));
    }

    /// Total evidence artifacts collected.
    #[must_use]
    pub fn total_artifacts(&self) -> usize {
        self.audit_events.len()
            + self.receipts.len()
            + self.decisions.len()
            + self.seeded_state.len()
            + self.mutations.len()
            + self.cleanup_verifications.len()
    }

    /// Check if any evidence was collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_artifacts() == 0 && self.log_lines.is_empty()
    }

    /// Serialize all evidence to JSON for reporting.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "audit_events": self.audit_events.len(),
            "receipts": self.receipts.len(),
            "decisions": self.decisions.len(),
            "log_lines": self.log_lines.len(),
            "seeded_state": self.seeded_state.len(),
            "mutations": self.mutations.len(),
            "cleanup_verifications": self.cleanup_verifications.len(),
            "total_artifacts": self.total_artifacts(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that the collector has at least one audit event of the given type.
///
/// # Panics
///
/// Panics if no audit event with the given type is found.
pub fn assert_evidence_has_audit_event(collector: &EvidenceCollector, event_type: &str) {
    assert!(
        collector
            .audit_events
            .iter()
            .any(|e| e.event_type == event_type),
        "expected audit event of type '{event_type}', found types: {:?}",
        collector
            .audit_events
            .iter()
            .map(|e| &e.event_type)
            .collect::<Vec<_>>()
    );
}

/// Assert that the collector has a receipt for the given request ID.
///
/// # Panics
///
/// Panics if no receipt with the given request ID is found.
pub fn assert_evidence_has_receipt(collector: &EvidenceCollector, request_id: &str) {
    assert!(
        collector
            .receipts
            .iter()
            .any(|r| r.request_id == request_id),
        "expected receipt for request '{request_id}', found: {:?}",
        collector
            .receipts
            .iter()
            .map(|r| &r.request_id)
            .collect::<Vec<_>>()
    );
}

/// Assert that all audit events are zone-scoped.
///
/// # Panics
///
/// Panics if any audit event is not zone-scoped.
pub fn assert_evidence_all_zone_scoped(collector: &EvidenceCollector) {
    let unscoped: Vec<&str> = collector
        .audit_events
        .iter()
        .filter(|e| !e.zone_scoped)
        .map(|e| e.event_type.as_str())
        .collect();
    assert!(
        unscoped.is_empty(),
        "expected all audit events to be zone-scoped, but these are not: {unscoped:?}"
    );
}

/// Assert that no evidence artifacts contain secret-like patterns.
///
/// # Panics
///
/// Panics if any secret pattern is found in the serialized evidence.
pub fn assert_evidence_no_secrets(collector: &EvidenceCollector, patterns: &[&str]) {
    let serialized = format!("{collector:?}");
    for pattern in patterns {
        assert!(
            !serialized.contains(pattern),
            "found secret pattern '{pattern}' in evidence artifacts"
        );
    }
}

/// Assert that the collector has at least N total artifacts.
///
/// # Panics
///
/// Panics if the total artifact count is less than expected.
pub fn assert_evidence_minimum_artifacts(collector: &EvidenceCollector, minimum: usize) {
    assert!(
        collector.total_artifacts() >= minimum,
        "expected at least {minimum} artifacts, got {}",
        collector.total_artifacts()
    );
}

/// Assert that all receipts for a given operation succeeded.
///
/// # Panics
///
/// Panics if any receipt for the operation failed.
pub fn assert_all_receipts_succeeded(collector: &EvidenceCollector, operation_id: &str) {
    let failed: Vec<&str> = collector
        .receipts
        .iter()
        .filter(|r| r.operation_id == operation_id && !r.success)
        .map(|r| r.request_id.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "expected all receipts for '{operation_id}' to succeed, but these failed: {failed:?}"
    );
}

/// Assert idempotency: duplicate receipts with the same key should exist.
///
/// # Panics
///
/// Panics if fewer than `expected_count` receipts share the given idempotency key.
pub fn assert_idempotent_receipts(
    collector: &EvidenceCollector,
    idempotency_key: &str,
    expected_count: usize,
) {
    let matching: Vec<_> = collector
        .receipts
        .iter()
        .filter(|r| r.idempotency_key.as_deref() == Some(idempotency_key))
        .collect();
    assert!(
        matching.len() >= expected_count,
        "expected at least {expected_count} receipts with idempotency key '{idempotency_key}', found {}",
        matching.len()
    );
}

/// Assert that a decision was recorded with the expected outcome.
///
/// # Panics
///
/// Panics if no matching decision is found.
pub fn assert_decision_recorded(
    collector: &EvidenceCollector,
    subject: &str,
    expected_approved: bool,
) {
    let found = collector.decisions.iter().find(|d| d.subject == subject);
    assert!(found.is_some(), "no decision found for subject '{subject}'");
    let decision = found.expect("checked above");
    assert_eq!(
        decision.approved,
        expected_approved,
        "decision for '{subject}' was {}, expected {}",
        if decision.approved {
            "approved"
        } else {
            "denied"
        },
        if expected_approved {
            "approved"
        } else {
            "denied"
        }
    );
}

/// Assert that a seeded resource was recorded.
///
/// # Panics
///
/// Panics if the seeded resource is missing.
pub fn assert_seeded_state_recorded(
    collector: &EvidenceCollector,
    resource: &str,
    identifier: &str,
) {
    assert!(
        collector
            .seeded_state
            .iter()
            .any(|seed| seed.resource == resource && seed.identifier == identifier),
        "expected seeded state for '{resource}/{identifier}', found: {:?}",
        collector
            .seeded_state
            .iter()
            .map(|seed| format!("{}/{}", seed.resource, seed.identifier))
            .collect::<Vec<_>>()
    );
}

/// Assert that a mutation was recorded.
///
/// # Panics
///
/// Panics if the mutation is missing.
pub fn assert_mutation_recorded(
    collector: &EvidenceCollector,
    operation: &str,
    resource: &str,
    identifier: &str,
) {
    assert!(
        collector.mutations.iter().any(|mutation| {
            mutation.operation == operation
                && mutation.resource == resource
                && mutation.identifier == identifier
        }),
        "expected mutation '{operation}' for '{resource}/{identifier}', found: {:?}",
        collector
            .mutations
            .iter()
            .map(|mutation| format!(
                "{}:{}/{}",
                mutation.operation, mutation.resource, mutation.identifier
            ))
            .collect::<Vec<_>>()
    );
}

/// Assert that all cleanup verifications passed.
///
/// # Panics
///
/// Panics if any cleanup verification failed.
pub fn assert_cleanup_verifications_passed(collector: &EvidenceCollector) {
    let failed: Vec<&str> = collector
        .cleanup_verifications
        .iter()
        .filter(|verification| !verification.passed)
        .map(|verification| verification.check_id.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "expected cleanup verification to pass, but these checks failed: {failed:?}"
    );
}

/// Assert that every mutation has at least one cleanup verification for the same resource.
///
/// # Panics
///
/// Panics if any mutation lacks teardown verification.
pub fn assert_mutations_have_cleanup_verifications(collector: &EvidenceCollector) {
    let missing: Vec<String> = collector
        .mutations
        .iter()
        .filter(|mutation| {
            !collector
                .cleanup_verifications
                .iter()
                .any(|verification| verification.resource == mutation.resource)
        })
        .map(|mutation| format!("{}/{}", mutation.resource, mutation.identifier))
        .collect();
    assert!(
        missing.is_empty(),
        "expected cleanup verification for every mutation, missing: {missing:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_empty_by_default() {
        let collector = EvidenceCollector::new();
        assert!(collector.is_empty());
        assert_eq!(collector.total_artifacts(), 0);
    }

    #[test]
    fn collector_records_audit_events() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "gmail.search", json!({"zone": "z:private"}));
        assert_eq!(collector.audit_events.len(), 1);
        assert_eq!(collector.total_artifacts(), 1);
        assert!(!collector.is_empty());
    }

    #[test]
    fn collector_records_receipts() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("req_1", "op_1", true);
        collector.record_receipt("req_2", "op_1", false);
        assert_eq!(collector.receipts.len(), 2);
    }

    #[test]
    fn collector_records_receipts_with_key() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt_with_key("req_1", "op_1", true, "idem_123");
        assert_eq!(
            collector.receipts[0].idempotency_key.as_deref(),
            Some("idem_123")
        );
    }

    #[test]
    fn collector_records_decisions() {
        let mut collector = EvidenceCollector::new();
        collector.record_decision("risky_op", true, "approved by user");
        assert_eq!(collector.decisions.len(), 1);
        assert!(collector.decisions[0].approved);
    }

    #[test]
    fn collector_to_json() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({}));
        collector.record_receipt("r1", "op_1", true);
        let j = collector.to_json();
        assert_eq!(j["audit_events"], 1);
        assert_eq!(j["receipts"], 1);
        assert_eq!(j["total_artifacts"], 2);
    }

    #[test]
    fn assert_audit_event_found() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "gmail.search", json!({}));
        assert_evidence_has_audit_event(&collector, "invoke");
    }

    #[test]
    #[should_panic(expected = "expected audit event of type")]
    fn assert_audit_event_missing() {
        let collector = EvidenceCollector::new();
        assert_evidence_has_audit_event(&collector, "invoke");
    }

    #[test]
    fn assert_receipt_found() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("req_42", "op_1", true);
        assert_evidence_has_receipt(&collector, "req_42");
    }

    #[test]
    fn assert_zone_scoped_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({}));
        assert_evidence_all_zone_scoped(&collector);
    }

    #[test]
    #[should_panic(expected = "zone-scoped")]
    fn assert_zone_scoped_fails() {
        let mut collector = EvidenceCollector::new();
        collector.record_unscoped_audit_event("invoke", "op_1", json!({}));
        assert_evidence_all_zone_scoped(&collector);
    }

    #[test]
    fn assert_no_secrets_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({"zone": "z:work"}));
        assert_evidence_no_secrets(&collector, &["sk-test-", "Bearer "]);
    }

    #[test]
    fn assert_minimum_artifacts() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({}));
        collector.record_receipt("r1", "op_1", true);
        assert_evidence_minimum_artifacts(&collector, 2);
    }

    #[test]
    fn assert_all_receipts_succeeded_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("r1", "op_1", true);
        collector.record_receipt("r2", "op_1", true);
        assert_all_receipts_succeeded(&collector, "op_1");
    }

    #[test]
    #[should_panic(expected = "these failed")]
    fn assert_all_receipts_succeeded_fails() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("r1", "op_1", true);
        collector.record_receipt("r2", "op_1", false);
        assert_all_receipts_succeeded(&collector, "op_1");
    }

    #[test]
    fn assert_idempotent_receipts_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt_with_key("r1", "op_1", true, "key_a");
        collector.record_receipt_with_key("r2", "op_1", true, "key_a");
        assert_idempotent_receipts(&collector, "key_a", 2);
    }

    #[test]
    fn assert_decision_recorded_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_decision("delete_account", false, "too dangerous");
        assert_decision_recorded(&collector, "delete_account", false);
    }

    #[test]
    #[should_panic(expected = "no decision found")]
    fn assert_decision_recorded_missing() {
        let collector = EvidenceCollector::new();
        assert_decision_recorded(&collector, "nonexistent", true);
    }

    #[test]
    fn unscoped_audit_event() {
        let mut collector = EvidenceCollector::new();
        collector.record_unscoped_audit_event("health", "system", json!({}));
        assert!(!collector.audit_events[0].zone_scoped);
    }

    #[test]
    fn log_lines_recorded() {
        let mut collector = EvidenceCollector::new();
        collector.record_log_line(json!({"level": "info", "msg": "test"}));
        assert_eq!(collector.log_lines.len(), 1);
    }

    #[test]
    fn collector_records_seeded_state_and_mutations() {
        let mut collector = EvidenceCollector::new();
        collector.record_seeded_state("users", "user-1", json!({"id": 1}));
        collector.record_mutation(
            FixtureMutationRecord::new(
                "update",
                "users",
                "user-1",
                "connector updates the seeded user row",
            )
            .with_after(json!({"id": 1, "name": "Alice Updated"})),
        );
        collector.record_cleanup_verification(
            "cleanup-users",
            "users",
            "query_row_digest",
            "seed digest matches the original payload",
            json!({"digest_match": true}),
            true,
        );

        assert_eq!(collector.seeded_state.len(), 1);
        assert_eq!(collector.mutations.len(), 1);
        assert_eq!(collector.cleanup_verifications.len(), 1);
        assert_seeded_state_recorded(&collector, "users", "user-1");
        assert_mutation_recorded(&collector, "update", "users", "user-1");
        assert_cleanup_verifications_passed(&collector);
        assert_mutations_have_cleanup_verifications(&collector);
    }

    #[test]
    #[should_panic(expected = "cleanup verification to pass")]
    fn cleanup_verifications_fail_when_any_check_fails() {
        let mut collector = EvidenceCollector::new();
        collector.record_cleanup_verification(
            "cleanup-temp-objects",
            "objects",
            "prefix_empty",
            "temporary objects are removed",
            json!({"remaining_keys": ["tmp/run-1.json"]}),
            false,
        );

        assert_cleanup_verifications_passed(&collector);
    }

    #[test]
    #[should_panic(expected = "missing")]
    fn mutations_require_cleanup_verification() {
        let mut collector = EvidenceCollector::new();
        collector.record_mutation(FixtureMutationRecord::new(
            "put",
            "objects",
            "tmp/run-1.json",
            "connector uploads a temporary object",
        ));

        assert_mutations_have_cleanup_verifications(&collector);
    }
}
