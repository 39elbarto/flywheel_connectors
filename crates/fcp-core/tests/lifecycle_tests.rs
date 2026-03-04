//! Lifecycle state machine unit tests with structured JSONL logging.
//!
//! These tests validate the connector lifecycle state machine per `docs/STANDARD_Testing_Logging.md`.
//! All tests emit structured JSONL logs and validate against the E2E schema.
//!
//! Coverage:
//! - Valid transition sequence (Pending → Installing → Canary → Production)
//! - Failed health → rollback (health below threshold triggers auto-rollback)
//! - Repeated failures → disabled state (circuit breaker behavior)

#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

use std::time::Instant;

use chrono::Utc;
use fcp_core::{
    CanaryPolicy, ConnectorId, HealthMetrics, LifecycleError, LifecycleRecord, LifecycleState,
    TransitionReason,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Context
// ─────────────────────────────────────────────────────────────────────────────

/// Test context for structured logging with connector lifecycle context.
struct TestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    connector_id: ConnectorId,
    version: semver::Version,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl TestContext {
    fn new(test_name: &str, connector_id: ConnectorId, version: semver::Version) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::lifecycle".to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            connector_id,
            version,
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn log_phase(&self, phase: &str, details: Option<serde_json::Value>) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let mut entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "connector_id": self.connector_id.to_string(),
            "version": self.version.to_string(),
            "result": "pass",
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(d) = details {
            entry["details"] = d;
        }

        self.capture.push_value(&entry).expect("log entry");
    }

    fn log_transition(&self, from: LifecycleState, to: LifecycleState, reason: &str) {
        self.log_phase(
            "transition",
            Some(json!({
                "from": from.as_str(),
                "to": to.as_str(),
                "reason": reason
            })),
        );
    }

    fn log_health_update(&self, health: &HealthMetrics) {
        self.log_phase(
            "health_update",
            Some(json!({
                "samples": health.samples,
                "successes": health.successes,
                "failures": health.failures,
                "success_rate": health.success_rate
            })),
        );
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: &T, expected: &T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}");
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn finalize(&self, result: &str) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "connector_id": self.connector_id.to_string(),
            "version": self.version.to_string(),
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });
        self.capture.push_value(&entry).expect("final log entry");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_connector_id() -> ConnectorId {
    ConnectorId::from_static("test:lifecycle:v1")
}

const fn test_version() -> semver::Version {
    semver::Version::new(1, 0, 0)
}

/// Create a lifecycle record transitioned to canary state.
fn create_canary_record(policy: CanaryPolicy) -> LifecycleRecord {
    let mut record =
        LifecycleRecord::new(test_connector_id(), test_version()).with_canary_policy(policy);

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("pending -> installing");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("installing -> canary");

    record
}

// ─────────────────────────────────────────────────────────────────────────────
// Valid Transition Sequence Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test the happy path: Pending → Installing → Canary → Production.
#[test]
fn test_valid_transition_sequence_to_production() {
    let mut ctx = TestContext::new(
        "valid_transition_sequence_to_production",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "happy_path_to_production"})),
    );

    // Create a new lifecycle record
    let mut record = LifecycleRecord::new(test_connector_id(), test_version()).with_canary_policy(
        CanaryPolicy::new()
            .with_promotion_threshold(90)
            .with_min_samples(5)
            .with_min_canary_duration(0),
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Pending,
        "Initial state should be Pending",
    );
    ctx.log_phase("assert", Some(json!({"state": "Pending"})));

    // Transition: Pending → Installing
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("pending -> installing");
    ctx.log_transition(
        LifecycleState::Pending,
        LifecycleState::Installing,
        "InstallComplete",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Installing,
        "Should be Installing after transition",
    );

    // Transition: Installing → Canary
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("installing -> canary");
    ctx.log_transition(
        LifecycleState::Installing,
        LifecycleState::Canary,
        "InstallComplete",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be Canary after transition",
    );

    // Add health samples
    for _ in 0..5 {
        record.update_health(true, Some(100));
    }
    ctx.log_health_update(&record.health);

    // Check auto-promotion eligibility
    ctx.assert_true(
        record.should_auto_promote(),
        "Should be eligible for auto-promotion",
    );

    // Transition: Canary → Production
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 100 },
        )
        .expect("canary -> production");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::Production,
        "AutoPromotion",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Should be Production after promotion",
    );

    ctx.assert_eq(
        &record.transitions.len(),
        &3,
        "Should have 3 transitions recorded",
    );

    ctx.finalize("pass");
}

/// Test manual promotion from canary to production.
#[test]
fn test_manual_promotion() {
    let mut ctx = TestContext::new("manual_promotion", test_connector_id(), test_version());

    ctx.log_phase("setup", Some(json!({"scenario": "manual_promotion"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Manual promotion (even without meeting thresholds)
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("canary -> production");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::Production,
        "ManualPromotion",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Should be Production after manual promotion",
    );

    // Verify transition reason is recorded
    let last_transition = record.transitions.last().expect("should have transitions");
    ctx.assert_eq(
        &last_transition.reason,
        &TransitionReason::ManualPromotion,
        "Transition reason should be ManualPromotion",
    );

    ctx.finalize("pass");
}

/// Test invalid transition is rejected.
#[test]
fn test_invalid_transition_rejected() {
    let mut ctx = TestContext::new(
        "invalid_transition_rejected",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "invalid_transition"})));

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());

    // Try to skip Installing and go directly to Production
    let result = record.transition(
        LifecycleState::Production,
        TransitionReason::ManualPromotion,
    );

    ctx.assert_true(
        result.is_err(),
        "Should reject Pending -> Production transition",
    );

    if let Err(LifecycleError::InvalidTransition { from, to }) = result {
        ctx.assert_eq(
            &from,
            &LifecycleState::Pending,
            "From state should be Pending",
        );
        ctx.assert_eq(
            &to,
            &LifecycleState::Production,
            "To state should be Production",
        );
        ctx.log_phase(
            "assert",
            Some(json!({
                "error": "InvalidTransition",
                "from": from.as_str(),
                "to": to.as_str()
            })),
        );
    }

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Failed Health → Rollback Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test automatic rollback when health drops below threshold.
#[test]
fn test_auto_rollback_on_health_failure() {
    let mut ctx = TestContext::new(
        "auto_rollback_on_health_failure",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "health_failure_rollback"})),
    );

    // Create canary with specific thresholds
    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_rollback_threshold(80)
            .with_min_samples(10),
    );

    ctx.log_phase(
        "config",
        Some(json!({
            "rollback_threshold": 80,
            "min_samples": 10
        })),
    );

    // Add failing health samples (70% success rate)
    for _ in 0..7 {
        record.update_health(true, Some(100));
    }
    for _ in 0..3 {
        record.update_health(false, Some(500));
    }

    ctx.log_health_update(&record.health);

    // Verify auto-rollback should trigger
    ctx.assert_true(
        record.should_auto_rollback(),
        "Should trigger auto-rollback with 70% success rate",
    );

    ctx.assert_eq(
        &record.health.success_rate,
        &70u8,
        "Success rate should be 70%",
    );

    // Execute rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 70,
                failure_reason: "Success rate below threshold".to_string(),
            },
        )
        .expect("canary -> rolled_back");

    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be RolledBack after health failure",
    );

    ctx.finalize("pass");
}

/// Test manual rollback from production.
#[test]
fn test_manual_rollback_from_production() {
    let mut ctx = TestContext::new(
        "manual_rollback_from_production",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "manual_rollback"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // First promote to production
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("canary -> production");

    // Then rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback {
                reason: Some("Emergency rollback due to customer reports".to_string()),
            },
        )
        .expect("production -> rolled_back");

    ctx.log_transition(
        LifecycleState::Production,
        LifecycleState::RolledBack,
        "ManualRollback",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be RolledBack after manual rollback",
    );

    ctx.finalize("pass");
}

/// Test recovery from rollback (retry with new canary).
#[test]
fn test_recovery_from_rollback() {
    let mut ctx = TestContext::new(
        "recovery_from_rollback",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "recovery_retry"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 75,
                failure_reason: "Test failure".to_string(),
            },
        )
        .expect("canary -> rolled_back");

    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback",
    );

    // Retry: RolledBack → Canary
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "1.0.1".to_string(),
            },
        )
        .expect("rolled_back -> canary");

    ctx.log_transition(
        LifecycleState::RolledBack,
        LifecycleState::Canary,
        "NewVersion",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be back in Canary for retry",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Repeated Failures → Disabled State Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test disabling a connector after repeated failures.
#[test]
fn test_disable_after_repeated_failures() {
    let mut ctx = TestContext::new(
        "disable_after_repeated_failures",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "repeated_failures_disable"})),
    );

    let mut record = create_canary_record(CanaryPolicy::new());

    // Simulate repeated rollbacks
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 60,
                failure_reason: "First failure".to_string(),
            },
        )
        .expect("first rollback");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback#1",
    );

    // Retry
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("retry canary");

    // Second rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 55,
                failure_reason: "Second failure".to_string(),
            },
        )
        .expect("second rollback");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback#2",
    );

    // After repeated failures, disable the connector
    record
        .transition(
            LifecycleState::Disabled,
            TransitionReason::Disabled {
                reason: "Repeated failures - circuit breaker triggered".to_string(),
            },
        )
        .expect("rolled_back -> disabled");
    ctx.log_transition(
        LifecycleState::RolledBack,
        LifecycleState::Disabled,
        "Disabled",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Disabled,
        "Should be Disabled after repeated failures",
    );

    ctx.assert_true(
        !record.state.is_active(),
        "Disabled state should not be active",
    );

    ctx.finalize("pass");
}

/// Test re-enabling a disabled connector.
#[test]
fn test_reenable_disabled_connector() {
    let mut ctx = TestContext::new(
        "reenable_disabled_connector",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "reenable"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Disable
    record
        .transition(
            LifecycleState::Disabled,
            TransitionReason::Disabled {
                reason: "Manual disable for maintenance".to_string(),
            },
        )
        .expect("canary -> disabled");

    // Re-enable by transitioning back to canary
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "1.0.2".to_string(),
            },
        )
        .expect("disabled -> canary");
    ctx.log_transition(
        LifecycleState::Disabled,
        LifecycleState::Canary,
        "NewVersion",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be Canary after re-enable",
    );

    ctx.assert_true(record.state.is_active(), "Canary state should be active");

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Metrics Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test health metrics accumulation and success rate calculation.
#[test]
fn test_health_metrics_calculation() {
    let mut ctx = TestContext::new(
        "health_metrics_calculation",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "health_calculation"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Add mixed health samples
    for i in 0..100 {
        let success = i < 95; // 95% success rate
        let latency = if success { 50 + (i % 50) } else { 1000 };
        record.update_health(success, Some(latency));
    }

    ctx.log_health_update(&record.health);

    ctx.assert_eq(&record.health.samples, &100, "Should have 100 samples");
    ctx.assert_eq(&record.health.successes, &95, "Should have 95 successes");
    ctx.assert_eq(&record.health.failures, &5, "Should have 5 failures");
    ctx.assert_eq(
        &record.health.success_rate,
        &95u8,
        "Success rate should be 95%",
    );
    ctx.assert_eq(
        &record.health.max_latency_ms,
        &1000,
        "Max latency should be 1000ms",
    );

    ctx.finalize("pass");
}

/// Test health reset when entering canary.
#[test]
fn test_health_reset() {
    let mut ctx = TestContext::new("health_reset", test_connector_id(), test_version());

    ctx.log_phase("setup", Some(json!({"scenario": "health_reset"})));

    let mut record = create_canary_record(CanaryPolicy::new());

    // Add some health data
    for _ in 0..50 {
        record.update_health(true, Some(100));
    }

    ctx.assert_eq(&record.health.samples, &50, "Should have 50 samples");

    // Reset health
    record.reset_health();
    ctx.log_phase("action", Some(json!({"action": "reset_health"})));

    ctx.assert_eq(&record.health.samples, &0, "Samples should be reset to 0");
    ctx.assert_eq(
        &record.health.successes,
        &0,
        "Successes should be reset to 0",
    );
    ctx.assert_eq(&record.health.failures, &0, "Failures should be reset to 0");

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Canary Policy Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test canary policy validation.
#[test]
fn test_canary_policy_validation() {
    let mut ctx = TestContext::new(
        "canary_policy_validation",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "policy_validation"})));

    // Valid policy
    let valid_policy = CanaryPolicy::new()
        .with_promotion_threshold(95)
        .with_rollback_threshold(80);

    ctx.assert_true(
        valid_policy.validate().is_ok(),
        "Valid policy should pass validation",
    );

    // Invalid policy (promotion <= rollback)
    let invalid_policy = CanaryPolicy::new()
        .with_promotion_threshold(80)
        .with_rollback_threshold(90);

    ctx.assert_true(
        invalid_policy.validate().is_err(),
        "Invalid policy should fail validation",
    );

    // Invalid traffic percentage
    let invalid_traffic = CanaryPolicy::new().with_canary_traffic_percent(150);

    ctx.assert_true(
        invalid_traffic.validate().is_err(),
        "Policy with traffic > 100% should fail",
    );

    ctx.finalize("pass");
}

/// Test auto-promotion threshold behavior.
#[test]
fn test_auto_promotion_threshold() {
    let mut ctx = TestContext::new(
        "auto_promotion_threshold",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "promotion_threshold"})));

    // Create canary with strict thresholds
    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_promotion_threshold(95)
            .with_min_samples(100)
            .with_min_canary_duration(0),
    );

    // Add 94 successes (below threshold)
    for _ in 0..94 {
        record.update_health(true, Some(100));
    }
    for _ in 0..6 {
        record.update_health(false, Some(100));
    }

    ctx.log_health_update(&record.health);
    ctx.assert_eq(
        &record.health.success_rate,
        &94u8,
        "Success rate should be 94%",
    );
    ctx.assert_true(
        !record.should_auto_promote(),
        "Should NOT auto-promote at 94%",
    );

    // Add more successes to reach 95%+
    record.reset_health();
    for _ in 0..96 {
        record.update_health(true, Some(100));
    }
    for _ in 0..4 {
        record.update_health(false, Some(100));
    }

    ctx.log_health_update(&record.health);
    ctx.assert_eq(
        &record.health.success_rate,
        &96u8,
        "Success rate should be 96%",
    );
    ctx.assert_true(record.should_auto_promote(), "Should auto-promote at 96%");

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Transition Audit Trail Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test that all transitions are recorded in the audit trail.
#[test]
fn test_transition_audit_trail() {
    let mut ctx = TestContext::new(
        "transition_audit_trail",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase("setup", Some(json!({"scenario": "audit_trail"})));

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());

    // Perform several transitions
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("t1");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("t2");
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 98 },
        )
        .expect("t3");
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback {
                reason: Some("Testing".to_string()),
            },
        )
        .expect("t4");

    // Verify audit trail
    ctx.assert_eq(
        &record.transitions.len(),
        &4,
        "Should have 4 transitions in audit trail",
    );

    // Check first transition
    let t1 = &record.transitions[0];
    ctx.assert_eq(&t1.from, &LifecycleState::Pending, "T1 from Pending");
    ctx.assert_eq(&t1.to, &LifecycleState::Installing, "T1 to Installing");

    // Check last transition
    let t4 = &record.transitions[3];
    ctx.assert_eq(&t4.from, &LifecycleState::Production, "T4 from Production");
    ctx.assert_eq(&t4.to, &LifecycleState::RolledBack, "T4 to RolledBack");

    // Log the full audit trail
    ctx.log_phase(
        "audit_trail",
        Some(json!({
            "transitions": record.transitions.iter().map(|t| {
                json!({
                    "from": t.from.as_str(),
                    "to": t.to.as_str(),
                    "timestamp": t.timestamp.to_rfc3339()
                })
            }).collect::<Vec<_>>()
        })),
    );

    ctx.finalize("pass");
}

/// Test transition timestamps are monotonically increasing.
#[test]
fn test_transition_timestamps() {
    let mut ctx = TestContext::new("transition_timestamps", test_connector_id(), test_version());

    ctx.log_phase("setup", Some(json!({"scenario": "timestamp_ordering"})));

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("t1");

    // Small delay to ensure different timestamps
    std::thread::sleep(std::time::Duration::from_millis(10));

    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("t2");

    ctx.assert_true(
        record.transitions[1].timestamp >= record.transitions[0].timestamp,
        "Timestamps should be monotonically non-decreasing",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Rollback/Retry Cycle Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test multiple rollback → retry → canary cycles with version tracking.
#[test]
fn test_multi_rollback_retry_cycle() {
    let mut ctx = TestContext::new(
        "multi_rollback_retry_cycle",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "multi_rollback_retry"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), test_version())
        .with_canary_policy(
            CanaryPolicy::new()
                .with_rollback_threshold(80)
                .with_min_samples(5),
        )
        .with_previous_version(semver::Version::new(0, 9, 0));

    // First deployment attempt
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");

    // Fails health check
    for _ in 0..5 {
        record.update_health(false, Some(500));
    }
    ctx.assert_true(
        record.should_auto_rollback(),
        "Should trigger auto-rollback",
    );

    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 0,
                failure_reason: "All requests failed".to_string(),
            },
        )
        .expect("rollback #1");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback#1",
    );

    // Retry with new version
    record.reset_health();
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "1.0.1".to_string(),
            },
        )
        .expect("retry canary");

    // Second attempt also fails
    for _ in 0..5 {
        record.update_health(false, Some(1000));
    }
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 0,
                failure_reason: "Still failing".to_string(),
            },
        )
        .expect("rollback #2");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "AutoRollback#2",
    );

    // Third attempt succeeds
    record.reset_health();
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.1".to_string(),
                to_version: "1.0.2".to_string(),
            },
        )
        .expect("retry canary #2");

    for _ in 0..5 {
        record.update_health(true, Some(50));
    }

    // Verify full transition history
    ctx.assert_eq(
        &record.transitions.len(),
        &6,
        "Should have 6 transitions (install, canary, rollback, retry, rollback, retry)",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should be in Canary on third attempt",
    );

    // Previous version should still be set
    ctx.assert_true(
        record.previous_version.is_some(),
        "Previous version should be preserved",
    );

    ctx.finalize("pass");
}

/// Test full lifecycle: install → canary → production → new version → canary → production.
#[test]
fn test_full_lifecycle_with_version_upgrade() {
    let mut ctx = TestContext::new(
        "full_lifecycle_version_upgrade",
        test_connector_id(),
        semver::Version::new(1, 0, 0),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "full_lifecycle_upgrade"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), semver::Version::new(1, 0, 0))
        .with_canary_policy(
            CanaryPolicy::new()
                .with_promotion_threshold(90)
                .with_min_samples(5)
                .with_min_canary_duration(0),
        );

    // Phase 1: Install and reach production
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install v1");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary v1");
    for _ in 0..10 {
        record.update_health(true, Some(50));
    }
    ctx.assert_true(
        record.should_auto_promote(),
        "V1 should be eligible for promotion",
    );
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 100 },
        )
        .expect("production v1");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::Production,
        "AutoPromotion",
    );

    // Phase 2: New version deployment
    record.reset_health();
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "2.0.0".to_string(),
            },
        )
        .expect("canary v2");

    for _ in 0..10 {
        record.update_health(true, Some(30));
    }
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 100 },
        )
        .expect("production v2");
    ctx.log_transition(
        LifecycleState::Canary,
        LifecycleState::Production,
        "AutoPromotion v2",
    );

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Should be in Production",
    );
    ctx.assert_eq(
        &record.transitions.len(),
        &5,
        "Should have 5 transitions total",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Crash Loop Detection Integration
// ─────────────────────────────────────────────────────────────────────────────

/// Test crash loop detector with record_crash_and_maybe_rollback.
#[test]
fn test_crash_loop_triggers_auto_rollback() {
    use fcp_core::CrashLoopDetector;

    let mut ctx = TestContext::new(
        "crash_loop_auto_rollback",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "crash_loop_rollback"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), test_version())
        .with_previous_version(semver::Version::new(0, 9, 0));
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");

    let mut detector = CrashLoopDetector::new(3, 60);
    let now = chrono::Utc::now();

    // First two crashes: no rollback yet
    let r1 = record
        .record_crash_and_maybe_rollback(&mut detector, now, "crash 1")
        .expect("crash 1");
    ctx.assert_true(!r1, "First crash should not trigger rollback");

    let r2 = record
        .record_crash_and_maybe_rollback(&mut detector, now, "crash 2")
        .expect("crash 2");
    ctx.assert_true(!r2, "Second crash should not trigger rollback");

    // Third crash triggers rollback
    let r3 = record
        .record_crash_and_maybe_rollback(&mut detector, now, "crash 3")
        .expect("crash 3");
    ctx.assert_true(r3, "Third crash should trigger rollback");
    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be RolledBack",
    );

    // Detector should be cleared after rollback
    ctx.assert_eq(
        &detector.crash_count_in_window(now),
        &0,
        "Detector should be cleared after rollback",
    );

    ctx.finalize("pass");
}

/// Test crash loop without previous version fails with NoRollbackTarget.
#[test]
fn test_crash_loop_no_rollback_target() {
    use fcp_core::CrashLoopDetector;

    let mut ctx = TestContext::new(
        "crash_loop_no_rollback_target",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "crash_loop_no_target"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), test_version());
    // No previous_version set
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");

    let mut detector = CrashLoopDetector::new(2, 60);
    let now = chrono::Utc::now();

    // First crash
    record
        .record_crash_and_maybe_rollback(&mut detector, now, "crash 1")
        .expect("crash 1 ok");

    // Second crash triggers threshold but no previous version
    let result = record.record_crash_and_maybe_rollback(&mut detector, now, "crash 2");
    ctx.assert_true(result.is_err(), "Should fail without rollback target");

    if let Err(LifecycleError::NoRollbackTarget) = result {
        ctx.log_phase(
            "assert",
            Some(json!({"error": "NoRollbackTarget", "state": record.state.as_str()})),
        );
    }

    // State should remain Canary (rollback not applied)
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "State should remain Canary",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Recovery Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Test that health recovers from unhealthy state.
#[test]
fn test_health_recovery_from_failures() {
    let mut ctx = TestContext::new(
        "health_recovery_from_failures",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "health_recovery"})),
    );

    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_rollback_threshold(80)
            .with_promotion_threshold(95)
            .with_min_samples(5),
    );

    // Start with failures
    for _ in 0..5 {
        record.update_health(false, Some(500));
    }
    ctx.assert_true(
        record.should_auto_rollback(),
        "Should trigger rollback initially",
    );
    ctx.log_health_update(&record.health);

    // Reset and recover with successes
    record.reset_health();
    for _ in 0..10 {
        record.update_health(true, Some(50));
    }
    ctx.assert_true(
        !record.should_auto_rollback(),
        "Should NOT trigger rollback after recovery",
    );
    ctx.assert_eq(
        &record.health.success_rate,
        &100u8,
        "Success rate should be 100% after recovery",
    );
    ctx.log_health_update(&record.health);

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Canary Duration and Auto-Promotion Interaction
// ─────────────────────────────────────────────────────────────────────────────

/// Test that auto-promotion requires both health AND duration thresholds.
#[test]
fn test_auto_promotion_requires_both_health_and_duration() {
    let mut ctx = TestContext::new(
        "auto_promotion_health_and_duration",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "promotion_dual_requirement"})),
    );

    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_promotion_threshold(90)
            .with_min_samples(5)
            .with_min_canary_duration(300), // 5 minutes
    );

    // Add excellent health data
    for _ in 0..10 {
        record.update_health(true, Some(20));
    }

    // Health is great but duration not met
    let now = chrono::Utc::now();
    ctx.assert_true(
        !record.should_auto_promote_at(now),
        "Should NOT promote before min duration",
    );

    // After duration has passed
    let future = now + chrono::Duration::seconds(600);
    ctx.assert_true(
        record.should_auto_promote_at(future),
        "Should promote after min duration",
    );

    ctx.finalize("pass");
}

/// Test that insufficient samples prevent promotion even after duration.
#[test]
fn test_auto_promotion_requires_min_samples() {
    let mut ctx = TestContext::new(
        "auto_promotion_min_samples",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "promotion_min_samples"})),
    );

    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_promotion_threshold(90)
            .with_min_samples(100)
            .with_min_canary_duration(0),
    );

    // Only 10 samples (below 100 minimum)
    for _ in 0..10 {
        record.update_health(true, Some(20));
    }

    ctx.assert_true(
        !record.should_auto_promote(),
        "Should NOT promote with insufficient samples",
    );

    // Add more to reach minimum
    for _ in 0..90 {
        record.update_health(true, Some(20));
    }

    ctx.assert_true(
        record.should_auto_promote(),
        "Should promote with sufficient samples",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Activation Sequence Simulation
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate a full activation sequence: install → canary → health check → promote → production.
#[test]
fn test_activation_full_sequence() {
    let mut ctx = TestContext::new(
        "activation_full_sequence",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "full_activation"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), test_version()).with_canary_policy(
        CanaryPolicy::new()
            .with_promotion_threshold(95)
            .with_rollback_threshold(80)
            .with_min_samples(10)
            .with_min_canary_duration(0),
    );

    // Phase 1: Install
    ctx.log_phase("install", Some(json!({"phase": "installing"})));
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Installing,
        "Phase 1: Installing",
    );

    // Phase 2: Enter canary
    ctx.log_phase("canary", Some(json!({"phase": "canary_entry"})));
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Phase 2: Canary",
    );
    ctx.assert_true(record.state.is_active(), "Canary should be active");

    // Phase 3: Health monitoring
    ctx.log_phase("health_check", Some(json!({"phase": "health_monitoring"})));
    for i in 0..10 {
        let success = i < 9; // 90% success
        record.update_health(success, Some(if success { 50 } else { 500 }));
    }
    ctx.log_health_update(&record.health);

    // Not at promotion threshold yet (90% < 95%)
    ctx.assert_true(
        !record.should_auto_promote(),
        "Should not promote at 90%",
    );
    ctx.assert_true(
        !record.should_auto_rollback(),
        "Should not rollback at 90%",
    );

    // Phase 4: More successes push above threshold
    record.reset_health();
    for _ in 0..10 {
        record.update_health(true, Some(30));
    }
    ctx.assert_true(
        record.should_auto_promote(),
        "Should promote at 100%",
    );

    // Phase 5: Promote to production
    ctx.log_phase("promote", Some(json!({"phase": "production_promotion"})));
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 100 },
        )
        .expect("production");
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Phase 5: Production",
    );
    ctx.assert_true(record.state.is_active(), "Production should be active");

    ctx.assert_eq(
        &record.transitions.len(),
        &3,
        "Should have exactly 3 transitions in audit trail",
    );

    ctx.finalize("pass");
}

/// Simulate activation failure during canary with automatic rollback.
#[test]
fn test_activation_failure_during_canary() {
    let mut ctx = TestContext::new(
        "activation_failure_canary",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "activation_failure"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), test_version())
        .with_canary_policy(
            CanaryPolicy::new()
                .with_rollback_threshold(80)
                .with_min_samples(5),
        )
        .with_previous_version(semver::Version::new(0, 9, 0));

    // Install and enter canary
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");

    // Simulate health degradation
    for i in 0..10 {
        let success = i < 3; // 30% success rate
        record.update_health(success, Some(if success { 100 } else { 2000 }));
    }
    ctx.log_health_update(&record.health);

    ctx.assert_true(
        record.should_auto_rollback(),
        "Should trigger auto-rollback at 30%",
    );

    // Execute rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 30,
                failure_reason: "Severe health degradation".to_string(),
            },
        )
        .expect("rollback");

    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be rolled back",
    );
    ctx.assert_true(!record.state.is_active(), "RolledBack should not be active");

    // Verify audit trail captures the full sequence
    ctx.assert_eq(
        &record.transitions.len(),
        &3,
        "Should have 3 transitions: install, canary, rollback",
    );

    // Verify the rollback transition has the right reason
    let last = record.transitions.last().unwrap();
    ctx.assert_eq(
        &last.from,
        &LifecycleState::Canary,
        "Rollback from Canary",
    );
    ctx.assert_eq(
        &last.to,
        &LifecycleState::RolledBack,
        "Rollback to RolledBack",
    );

    ctx.finalize("pass");
}

/// Test disabling after multiple failed activation attempts.
#[test]
fn test_disable_after_repeated_activation_failures() {
    let mut ctx = TestContext::new(
        "disable_after_repeated_failures",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "repeated_failures_disable"})),
    );

    let mut record = create_canary_record(
        CanaryPolicy::new()
            .with_rollback_threshold(80)
            .with_min_samples(3),
    );

    // First attempt fails
    for _ in 0..3 {
        record.update_health(false, Some(500));
    }
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 0,
                failure_reason: "attempt 1".to_string(),
            },
        )
        .expect("rollback 1");

    // Second attempt
    record.reset_health();
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("retry 1");
    for _ in 0..3 {
        record.update_health(false, Some(500));
    }
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 0,
                failure_reason: "attempt 2".to_string(),
            },
        )
        .expect("rollback 2");

    // Third attempt
    record.reset_health();
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("retry 2");
    for _ in 0..3 {
        record.update_health(false, Some(500));
    }
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 0,
                failure_reason: "attempt 3".to_string(),
            },
        )
        .expect("rollback 3");

    // After 3 failed attempts, disable
    record
        .transition(
            LifecycleState::Disabled,
            TransitionReason::Disabled {
                reason: "Circuit breaker: 3 consecutive rollbacks".to_string(),
            },
        )
        .expect("disable");

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Disabled,
        "Should be disabled",
    );
    ctx.assert_true(!record.state.is_active(), "Disabled should not be active");

    // Full audit trail: install, canary (from create_canary_record), rollback1, retry1,
    // rollback2, retry2, rollback3, disable = 8
    ctx.assert_eq(
        &record.transitions.len(),
        &8,
        "Should have 8 transitions in audit trail",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Serde Persistence Simulation
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate saving and loading a lifecycle record (persistence).
#[test]
fn test_lifecycle_record_persistence_roundtrip() {
    let mut ctx = TestContext::new(
        "persistence_roundtrip",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "persistence"})),
    );

    // Create record with state
    let mut record = LifecycleRecord::new(test_connector_id(), test_version())
        .with_canary_policy(
            CanaryPolicy::new()
                .with_promotion_threshold(95)
                .with_min_samples(50),
        )
        .with_previous_version(semver::Version::new(0, 9, 0));

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");
    for _ in 0..10 {
        record.update_health(true, Some(100));
    }

    // Serialize (simulate save)
    let json_str = serde_json::to_string(&record).expect("serialize");
    ctx.log_phase(
        "serialize",
        Some(json!({"json_length": json_str.len()})),
    );

    // Deserialize (simulate load)
    let loaded: LifecycleRecord = serde_json::from_str(&json_str).expect("deserialize");

    // Verify all state is preserved
    ctx.assert_eq(
        &loaded.state,
        &LifecycleState::Canary,
        "State preserved",
    );
    ctx.assert_eq(
        &loaded.version,
        &semver::Version::new(1, 0, 0),
        "Version preserved",
    );
    ctx.assert_eq(
        &loaded.transitions.len(),
        &2,
        "Transitions preserved",
    );
    ctx.assert_eq(
        &loaded.health.samples,
        &10,
        "Health samples preserved",
    );
    ctx.assert_eq(
        &loaded.health.success_rate,
        &100u8,
        "Health success rate preserved",
    );
    ctx.assert_eq(
        &loaded.canary_policy.promotion_threshold,
        &95u8,
        "Policy preserved",
    );
    ctx.assert_true(
        loaded.previous_version.is_some(),
        "Previous version preserved",
    );
    ctx.assert_eq(
        loaded.previous_version.as_ref().unwrap(),
        &semver::Version::new(0, 9, 0),
        "Previous version value preserved",
    );

    ctx.finalize("pass");
}

/// Test that LifecycleStatus serializes correctly for API responses.
#[test]
fn test_lifecycle_status_api_response_format() {
    use fcp_core::{CrashLoopDetector, LifecycleStatus};

    let mut ctx = TestContext::new(
        "status_api_response",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "status_api"})),
    );

    let mut record = LifecycleRecord::new(test_connector_id(), test_version())
        .with_canary_policy(
            CanaryPolicy::new()
                .with_promotion_threshold(90)
                .with_min_samples(5)
                .with_min_canary_duration(0),
        )
        .with_previous_version(semver::Version::new(0, 9, 0));

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("install");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("canary");
    for _ in 0..10 {
        record.update_health(true, Some(50));
    }

    let mut detector = CrashLoopDetector::new(5, 300);
    let now = chrono::Utc::now();
    let status = LifecycleStatus::from_record(&record, now, detector.is_crash_loop(now));

    // Serialize status to JSON (API response format)
    let json_str = serde_json::to_string_pretty(&status).expect("serialize status");
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("parse json");

    ctx.assert_true(
        parsed["connector_id"].is_string(),
        "connector_id should be string",
    );
    ctx.assert_eq(
        &parsed["state"].as_str().unwrap(),
        &"canary",
        "state should be canary",
    );
    ctx.assert_true(
        parsed["auto_promote_pending"].as_bool().unwrap(),
        "auto_promote_pending should be true",
    );
    ctx.assert_true(
        !parsed["auto_rollback_pending"].as_bool().unwrap(),
        "auto_rollback_pending should be false",
    );
    ctx.assert_true(
        !parsed["crash_loop_detected"].as_bool().unwrap(),
        "crash_loop_detected should be false",
    );
    ctx.assert_true(
        parsed["rollback_target_version"].is_string(),
        "rollback_target_version should be present",
    );
    ctx.assert_true(
        parsed["canary_expires_in_secs"].is_number(),
        "canary_expires_in_secs should be present",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Production Rollback with Reason Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Test that production rollback records the reason in the audit trail.
#[test]
fn test_production_rollback_reason_in_audit() {
    let mut ctx = TestContext::new(
        "production_rollback_reason",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "production_rollback_audit"})),
    );

    let mut record = create_canary_record(CanaryPolicy::new());
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("production");

    let rollback_reason = "Critical bug in payment processing detected by monitoring";
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback {
                reason: Some(rollback_reason.to_string()),
            },
        )
        .expect("rollback");

    // Verify reason is captured in the last transition
    let last = record.transitions.last().unwrap();
    if let TransitionReason::ManualRollback { reason } = &last.reason {
        ctx.assert_true(
            reason.is_some(),
            "Rollback reason should be present",
        );
        ctx.assert_eq(
            reason.as_ref().unwrap(),
            &rollback_reason.to_string(),
            "Rollback reason should match",
        );
    } else {
        panic!("Expected ManualRollback reason");
    }

    ctx.finalize("pass");
}

/// Test uninstallation from various states with audit preservation.
#[test]
fn test_uninstall_preserves_full_history() {
    let mut ctx = TestContext::new(
        "uninstall_history_preservation",
        test_connector_id(),
        test_version(),
    );

    ctx.log_phase(
        "setup",
        Some(json!({"scenario": "uninstall_audit"})),
    );

    let mut record = create_canary_record(CanaryPolicy::new());
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("production");

    // Uninstall from production
    record
        .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
        .expect("uninstall");

    ctx.assert_eq(
        &record.state,
        &LifecycleState::Uninstalled,
        "Should be uninstalled",
    );
    ctx.assert_true(
        !record.state.is_active(),
        "Uninstalled should not be active",
    );

    // Full history is preserved
    ctx.assert_eq(
        &record.transitions.len(),
        &4,
        "Should have 4 transitions: install, canary, production, uninstall",
    );

    // Verify no further transitions are possible
    let result = record.transition(LifecycleState::Canary, TransitionReason::InstallComplete);
    ctx.assert_true(
        result.is_err(),
        "Should not be able to transition from Uninstalled",
    );

    ctx.finalize("pass");
}
