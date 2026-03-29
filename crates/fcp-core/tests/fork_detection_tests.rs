//! Unit tests for connector state fork detection (bd-3frf).
//!
//! # Coverage
//!
//! - Single head passes (no fork detected)
//! - Forked heads detected (multiple objects with same `prev`)
//! - Resolution clears fork state
//!
//! # Logging
//!
//! All tests emit structured JSONL per `docs/STANDARD_Testing_Logging.md`.

mod support;

use chrono::Utc;
use fcp_core::{
    ConnectorId, ConnectorStateModel, CrdtType, ForkEvent, ForkResolution, ForkResolutionOutcome,
    ObjectId, StateForkDetectionResult, StateForkDetector, ZoneId,
};
use std::time::Instant;
use support::LogCapture;

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn test_connector_id() -> ConnectorId {
    ConnectorId::from_static("fcp.test:fork-detection:v1")
}

/// Test context for structured logging.
struct TestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    connector_id: ConnectorId,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl TestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::connector_state::fork_detection".to_string(),
            correlation_id: format!(
                "fork-{}-{}",
                std::process::id(),
                Utc::now().timestamp_millis()
            ),
            connector_id: test_connector_id(),
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    fn assert_true(&mut self, condition: bool, message: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("Assertion failed: {message}");
        }
    }

    fn assert_eq<T: PartialEq + std::fmt::Debug>(&mut self, left: &T, right: &T, message: &str) {
        if left == right {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("Assertion failed: {message} - left: {left:?}, right: {right:?}");
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn finish(&self, details: &serde_json::Value) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let passed = self.assertions_failed == 0;

        self.capture.push_line(
            &serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "level": if passed { "info" } else { "error" },
                "test_name": &self.test_name,
                "module": &self.module,
                "phase": "verify",
                "correlation_id": &self.correlation_id,
                "result": if passed { "pass" } else { "fail" },
                "duration_ms": duration_ms,
                "assertions": {
                    "passed": self.assertions_passed,
                    "failed": self.assertions_failed
                },
                "details": details
            })
            .to_string(),
        );

        self.capture
            .validate_jsonl()
            .expect("JSONL schema validation");
    }
}

#[test]
fn single_head_no_fork_detected() {
    let mut ctx = TestContext::new("single_head_no_fork_detected");
    let mut detector = StateForkDetector::new();

    // Create a linear chain: genesis -> obj1 -> obj2
    let genesis = test_object_id("genesis");
    let obj1 = test_object_id("obj1");
    let obj2 = test_object_id("obj2");

    detector.register(genesis, None, 0, 100);
    detector.register(obj1, Some(genesis), 1, 100);
    detector.register(obj2, Some(obj1), 2, 100);

    let result = detector.detect_fork(ZoneId::work(), ctx.connector_id.clone(), 1_700_000_000);

    ctx.assert_true(!result.is_fork(), "Single head should not detect fork");

    if let StateForkDetectionResult::NoFork { head, seq } = &result {
        ctx.assert_eq(head, &obj2, "Head should be obj2");
        ctx.assert_eq(seq, &2, "Seq should be 2");
    }

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "head": obj2.to_string(),
        "seq": 2,
        "fork_detected": false
    }));
}

#[test]
fn forked_heads_detected() {
    let mut ctx = TestContext::new("forked_heads_detected");
    let mut detector = StateForkDetector::new();

    // Create a fork: genesis -> branch_a AND genesis -> branch_b
    let genesis = test_object_id("genesis");
    let branch_a = test_object_id("branch_a");
    let branch_b = test_object_id("branch_b");

    detector.register(genesis, None, 0, 100);
    detector.register(branch_a, Some(genesis), 1, 101);
    detector.register(branch_b, Some(genesis), 1, 102);

    let result = detector.detect_fork(ZoneId::work(), ctx.connector_id.clone(), 1_700_000_000);

    ctx.assert_true(result.is_fork(), "Forked heads should be detected");

    let fork = result.fork_event().expect("Fork event should exist");
    ctx.assert_eq(&fork.common_prev, &genesis, "Common prev should be genesis");
    ctx.assert_eq(&fork.fork_seq, &1, "Fork seq should be 1");
    ctx.assert_true(
        (fork.branch_a == branch_a && fork.branch_b == branch_b)
            || (fork.branch_a == branch_b && fork.branch_b == branch_a),
        "Branches should be branch_a and branch_b",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "fork_detected": true,
        "common_prev": genesis.to_string(),
        "branch_a": fork.branch_a.to_string(),
        "branch_b": fork.branch_b.to_string(),
        "fork_seq": fork.fork_seq
    }));
}

#[test]
fn resolution_by_lease_clears_fork_state() {
    let mut ctx = TestContext::new("resolution_by_lease_clears_fork_state");
    let mut detector = StateForkDetector::new();

    // Create a fork with different lease_seq values
    let genesis = test_object_id("genesis");
    let branch_a = test_object_id("branch_a");
    let branch_b = test_object_id("branch_b");

    detector.register(genesis, None, 0, 100);
    detector.register(branch_a, Some(genesis), 1, 200); // Higher lease_seq
    detector.register(branch_b, Some(genesis), 1, 150);

    let result = detector.detect_fork(ZoneId::work(), ctx.connector_id.clone(), 1_700_000_000);
    let fork = result.fork_event().expect("Fork should be detected");

    // Resolve using ChooseByLease
    let outcome = detector.resolve(
        fork,
        ForkResolution::ChooseByLease,
        &ConnectorStateModel::SingletonWriter,
        1_700_000_001,
    );

    ctx.assert_true(outcome.resolved, "Resolution should succeed");
    ctx.assert_eq(
        &outcome.winning_head,
        &Some(branch_a),
        "Winning head should be branch_a (higher lease_seq)",
    );
    ctx.assert_eq(
        &outcome.strategy,
        &ForkResolution::ChooseByLease,
        "Strategy should be ChooseByLease",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "resolution_strategy": "choose_by_lease",
        "resolved": outcome.resolved,
        "winning_head": branch_a.to_string(),
        "lease_seq_a": 200,
        "lease_seq_b": 150
    }));
}

#[test]
fn manual_resolution_selects_specified_head() {
    let mut ctx = TestContext::new("manual_resolution_selects_specified_head");
    let mut detector = StateForkDetector::new();

    // Create a fork with equal lease_seq values (requires manual resolution)
    let genesis = test_object_id("genesis");
    let branch_a = test_object_id("branch_a");
    let branch_b = test_object_id("branch_b");

    detector.register(genesis, None, 0, 100);
    detector.register(branch_a, Some(genesis), 1, 100); // Same lease_seq
    detector.register(branch_b, Some(genesis), 1, 100); // Same lease_seq

    let result = detector.detect_fork(ZoneId::work(), ctx.connector_id.clone(), 1_700_000_000);
    let fork = result.fork_event().expect("Fork should be detected");

    // Manually select branch_b as winner
    let outcome = detector.resolve_manual(fork, branch_b, 1_700_000_001);

    ctx.assert_true(outcome.resolved, "Manual resolution should succeed");
    ctx.assert_eq(
        &outcome.winning_head,
        &Some(branch_b),
        "Winning head should be branch_b",
    );
    ctx.assert_eq(
        &outcome.strategy,
        &ForkResolution::ManualResolution,
        "Strategy should be ManualResolution",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "resolution_strategy": "manual",
        "resolved": outcome.resolved,
        "winning_head": branch_b.to_string(),
        "selected_by_operator": true
    }));
}

#[test]
fn crdt_merge_valid_for_crdt_model() {
    let mut ctx = TestContext::new("crdt_merge_valid_for_crdt_model");

    // Verify CrdtMerge is only valid for CRDT state models
    ctx.assert_true(
        ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        }),
        "CrdtMerge should be valid for CRDT model",
    );

    ctx.assert_true(
        !ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::SingletonWriter),
        "CrdtMerge should not be valid for SingletonWriter model",
    );

    ctx.assert_true(
        !ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::Stateless),
        "CrdtMerge should not be valid for Stateless model",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "strategy": "crdt_merge",
        "valid_for_crdt": true,
        "valid_for_singleton": false,
        "valid_for_stateless": false
    }));
}

#[test]
fn lease_tie_requires_manual_resolution() {
    let mut ctx = TestContext::new("lease_tie_requires_manual_resolution");
    let mut detector = StateForkDetector::new();

    // Create a fork with equal lease_seq values
    let genesis = test_object_id("genesis");
    let branch_a = test_object_id("branch_a");
    let branch_b = test_object_id("branch_b");

    detector.register(genesis, None, 0, 100);
    detector.register(branch_a, Some(genesis), 1, 100); // Same lease_seq
    detector.register(branch_b, Some(genesis), 1, 100); // Same lease_seq

    let result = detector.detect_fork(ZoneId::work(), ctx.connector_id.clone(), 1_700_000_000);
    let fork = result.fork_event().expect("Fork should be detected");

    // Try to resolve using ChooseByLease - should fail due to tie
    let outcome = detector.resolve(
        fork,
        ForkResolution::ChooseByLease,
        &ConnectorStateModel::SingletonWriter,
        1_700_000_001,
    );

    ctx.assert_true(!outcome.resolved, "Lease tie should not auto-resolve");
    ctx.assert_true(
        outcome
            .failure_reason
            .as_ref()
            .is_some_and(|r| r.contains("tie")),
        "Failure reason should mention tie",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "resolution_strategy": "choose_by_lease",
        "resolved": false,
        "reason": "lease_seq tie",
        "lease_seq_a": 100,
        "lease_seq_b": 100
    }));
}

#[test]
fn fork_event_serialization_roundtrip() {
    let mut ctx = TestContext::new("fork_event_serialization_roundtrip");

    let fork = ForkEvent::new(
        test_object_id("prev"),
        test_object_id("a"),
        test_object_id("b"),
        42,
        1_700_000_000,
        ZoneId::work(),
        test_connector_id(),
    );

    let json = serde_json::to_string(&fork).expect("serialize");
    let decoded: ForkEvent = serde_json::from_str(&json).expect("deserialize");

    ctx.assert_eq(
        &decoded.common_prev,
        &fork.common_prev,
        "common_prev roundtrip",
    );
    ctx.assert_eq(&decoded.branch_a, &fork.branch_a, "branch_a roundtrip");
    ctx.assert_eq(&decoded.branch_b, &fork.branch_b, "branch_b roundtrip");
    ctx.assert_eq(&decoded.fork_seq, &fork.fork_seq, "fork_seq roundtrip");
    ctx.assert_eq(
        &decoded.detected_at,
        &fork.detected_at,
        "detected_at roundtrip",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "serialization": "json",
        "roundtrip_success": true,
        "fork_seq": fork.fork_seq
    }));
}

#[test]
fn resolution_outcome_success_structure() {
    let mut ctx = TestContext::new("resolution_outcome_success_structure");

    let fork = ForkEvent::new(
        test_object_id("prev"),
        test_object_id("a"),
        test_object_id("b"),
        10,
        1_700_000_000,
        ZoneId::work(),
        test_connector_id(),
    );

    let outcome = ForkResolutionOutcome::success(
        fork,
        ForkResolution::ChooseByLease,
        test_object_id("a"),
        1_700_000_001,
    );

    ctx.assert_true(outcome.resolved, "Success outcome should be resolved");
    ctx.assert_eq(
        &outcome.winning_head,
        &Some(test_object_id("a")),
        "Winning head should be set",
    );
    ctx.assert_true(
        outcome.failure_reason.is_none(),
        "No failure reason for success",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "outcome_type": "success",
        "resolved": true,
        "winning_head": test_object_id("a").to_string()
    }));
}

#[test]
fn resolution_outcome_failure_structure() {
    let mut ctx = TestContext::new("resolution_outcome_failure_structure");

    let fork = ForkEvent::new(
        test_object_id("prev"),
        test_object_id("a"),
        test_object_id("b"),
        10,
        1_700_000_000,
        ZoneId::work(),
        test_connector_id(),
    );

    let outcome = ForkResolutionOutcome::failure(
        fork,
        ForkResolution::ManualResolution,
        1_700_000_001,
        "test failure reason",
    );

    ctx.assert_true(!outcome.resolved, "Failure outcome should not be resolved");
    ctx.assert_true(
        outcome.winning_head.is_none(),
        "No winning head for failure",
    );
    ctx.assert_eq(
        &outcome.failure_reason.as_deref(),
        &Some("test failure reason"),
        "Failure reason should be set",
    );

    ctx.finish(&serde_json::json!({
        "connector_id": ctx.connector_id.to_string(),
        "outcome_type": "failure",
        "resolved": false,
        "failure_reason": "test failure reason"
    }));
}
