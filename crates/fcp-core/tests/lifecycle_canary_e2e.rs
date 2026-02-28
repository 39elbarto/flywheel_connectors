//! E2E canary rollout and rollback scenarios.
//!
//! These tests verify the connector lifecycle canary deployment flow with
//! health-based promotion and automatic rollback.
//!
//! Per `docs/STANDARD_Testing_Logging.md`, all tests emit structured JSONL logs
//! and persist artifacts for validation with `fcp_conformance::schemas::validate_e2e_log_jsonl`.
//!
//! ## Scenarios
//!
//! 1. Healthy canary promotes to production
//! 2. Unhealthy canary triggers automatic rollback
//! 3. Multi-version deployment with rollback to previous version

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use fcp_core::{
    CanaryPolicy, ConnectorId, HealthMetrics, LifecycleError, LifecycleManager, LifecycleRecord,
    LifecycleState, LifecycleStatus, TransitionReason,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use tokio::sync::RwLock;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// E2E test context with structured logging and multi-version tracking.
struct E2ETestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl E2ETestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::lifecycle::e2e".to_string(),
            correlation_id: Uuid::new_v4().to_string(),
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

    fn log_connector_state(
        &self,
        connector_id: &ConnectorId,
        version: &semver::Version,
        state: LifecycleState,
        health: &HealthMetrics,
    ) {
        self.log_phase(
            "connector_state",
            Some(json!({
                "connector_id": connector_id.to_string(),
                "version": version.to_string(),
                "state": state.as_str(),
                "health": {
                    "samples": health.samples,
                    "success_rate": health.success_rate,
                    "successes": health.successes,
                    "failures": health.failures
                }
            })),
        );
    }

    fn log_transition(
        &self,
        connector_id: &ConnectorId,
        version: &semver::Version,
        from: LifecycleState,
        to: LifecycleState,
        reason: &str,
    ) {
        self.log_phase(
            "state_transition",
            Some(json!({
                "connector_id": connector_id.to_string(),
                "version": version.to_string(),
                "from": from.as_str(),
                "to": to.as_str(),
                "reason": reason
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
// Mock Lifecycle Manager
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory lifecycle manager for testing.
struct MockLifecycleManager {
    records: RwLock<std::collections::HashMap<ConnectorId, LifecycleRecord>>,
}

impl MockLifecycleManager {
    fn new() -> Self {
        Self {
            records: RwLock::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl LifecycleManager for MockLifecycleManager {
    async fn get(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, LifecycleError> {
        let records = self.records.read().await;
        Ok(records.get(connector_id).cloned())
    }

    async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError> {
        self.records
            .write()
            .await
            .insert(record.connector_id.clone(), record.clone());
        Ok(())
    }

    async fn promote(&self, connector_id: &ConnectorId) -> Result<LifecycleRecord, LifecycleError> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;

        record.transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )?;
        let result = record.clone();
        drop(records);
        Ok(result)
    }

    async fn rollback(
        &self,
        connector_id: &ConnectorId,
        reason: Option<String>,
    ) -> Result<LifecycleRecord, LifecycleError> {
        let mut records = self.records.write().await;
        let record = records
            .get_mut(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;

        record.transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback { reason },
        )?;
        let result = record.clone();
        drop(records);
        Ok(result)
    }

    async fn status(&self, connector_id: &ConnectorId) -> Result<LifecycleStatus, LifecycleError> {
        let records = self.records.read().await;
        let record = records
            .get(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;

        let status = LifecycleStatus {
            connector_id: connector_id.clone(),
            state: record.state,
            version: record.version.clone(),
            health: record.health.clone(),
            auto_promote_pending: record.should_auto_promote(),
            auto_rollback_pending: record.should_auto_rollback(),
            canary_expires_in_secs: None,
        };
        drop(records);
        Ok(status)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_connector_id() -> ConnectorId {
    ConnectorId::from_static("test:canary:v1")
}

const fn version_1_0() -> semver::Version {
    semver::Version::new(1, 0, 0)
}

const fn version_1_1() -> semver::Version {
    semver::Version::new(1, 1, 0)
}

/// Simulate health samples for a connector.
fn add_health_samples(record: &mut LifecycleRecord, successes: u32, failures: u32) {
    for _ in 0..successes {
        record.update_health(true, Some(100));
    }
    for _ in 0..failures {
        record.update_health(false, Some(500));
    }
}

/// Deploy a connector version to canary state.
async fn deploy_to_canary(
    manager: &MockLifecycleManager,
    connector_id: ConnectorId,
    version: semver::Version,
    policy: CanaryPolicy,
) -> LifecycleRecord {
    let mut record = LifecycleRecord::new(connector_id, version).with_canary_policy(policy);

    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("pending -> installing");
    record
        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
        .expect("installing -> canary");

    manager.save(&record).await.expect("save record");
    record
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Healthy Canary Promotes to Production
// ─────────────────────────────────────────────────────────────────────────────

/// Test scenario: A healthy canary connector should be automatically promoted to production
/// once it meets the promotion threshold and minimum sample requirements.
#[fcp_async_core::runtime::test]
async fn test_healthy_canary_promotes_to_production() {
    let mut ctx = E2ETestContext::new("healthy_canary_promotes_to_production");
    let connector_id = test_connector_id();
    let version = version_1_0();

    ctx.log_phase(
        "setup",
        Some(json!({
            "scenario": "healthy_canary_promotion",
            "connector_id": connector_id.to_string(),
            "version": version.to_string()
        })),
    );

    // Create lifecycle manager
    let manager = Arc::new(MockLifecycleManager::new());

    // Deploy with relaxed thresholds for testing
    let policy = CanaryPolicy::new()
        .with_promotion_threshold(90)
        .with_rollback_threshold(70)
        .with_min_samples(10)
        .with_min_canary_duration(0);

    ctx.log_phase(
        "config",
        Some(json!({
            "promotion_threshold": 90,
            "rollback_threshold": 70,
            "min_samples": 10
        })),
    );

    // Deploy to canary
    let mut record =
        deploy_to_canary(&manager, connector_id.clone(), version.clone(), policy).await;

    ctx.log_transition(
        &connector_id,
        &version,
        LifecycleState::Pending,
        LifecycleState::Canary,
        "deployment",
    );

    // Simulate healthy traffic (95% success rate)
    add_health_samples(&mut record, 95, 5);
    manager.save(&record).await.expect("save health update");

    ctx.log_connector_state(&connector_id, &version, record.state, &record.health);

    // Verify promotion eligibility
    ctx.assert_eq(
        &record.health.success_rate,
        &95u8,
        "Success rate should be 95%",
    );
    ctx.assert_true(
        record.should_auto_promote(),
        "Should be eligible for auto-promotion",
    );
    ctx.assert_true(
        !record.should_auto_rollback(),
        "Should NOT be eligible for rollback",
    );

    // Execute promotion
    record
        .transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 95 },
        )
        .expect("canary -> production");
    manager.save(&record).await.expect("save promotion");

    ctx.log_transition(
        &connector_id,
        &version,
        LifecycleState::Canary,
        LifecycleState::Production,
        "auto_promotion",
    );

    // Verify final state
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Production,
        "Should be in Production state",
    );
    ctx.assert_true(record.state.is_active(), "Production should be active");

    // Verify via manager status
    let status = manager.status(&connector_id).await.expect("get status");
    ctx.assert_eq(
        &status.state,
        &LifecycleState::Production,
        "Manager status should show Production",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Unhealthy Canary Triggers Automatic Rollback
// ─────────────────────────────────────────────────────────────────────────────

/// Test scenario: An unhealthy canary connector should trigger automatic rollback
/// when health drops below the rollback threshold.
#[fcp_async_core::runtime::test]
async fn test_unhealthy_canary_triggers_rollback() {
    let mut ctx = E2ETestContext::new("unhealthy_canary_triggers_rollback");
    let connector_id = test_connector_id();
    let version = version_1_1();

    ctx.log_phase(
        "setup",
        Some(json!({
            "scenario": "unhealthy_canary_rollback",
            "connector_id": connector_id.to_string(),
            "version": version.to_string()
        })),
    );

    let manager = Arc::new(MockLifecycleManager::new());

    // Deploy with thresholds that will trigger rollback
    let policy = CanaryPolicy::new()
        .with_promotion_threshold(95)
        .with_rollback_threshold(80)
        .with_min_samples(10)
        .with_min_canary_duration(0);

    ctx.log_phase(
        "config",
        Some(json!({
            "promotion_threshold": 95,
            "rollback_threshold": 80,
            "min_samples": 10
        })),
    );

    // Deploy to canary
    let mut record =
        deploy_to_canary(&manager, connector_id.clone(), version.clone(), policy).await;

    ctx.log_transition(
        &connector_id,
        &version,
        LifecycleState::Pending,
        LifecycleState::Canary,
        "deployment",
    );

    // Simulate unhealthy traffic (60% success rate - below rollback threshold)
    add_health_samples(&mut record, 60, 40);
    manager.save(&record).await.expect("save health update");

    ctx.log_connector_state(&connector_id, &version, record.state, &record.health);

    // Verify rollback eligibility
    ctx.assert_eq(
        &record.health.success_rate,
        &60u8,
        "Success rate should be 60%",
    );
    ctx.assert_true(
        !record.should_auto_promote(),
        "Should NOT be eligible for promotion",
    );
    ctx.assert_true(
        record.should_auto_rollback(),
        "Should be eligible for auto-rollback",
    );

    // Execute rollback
    record
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 60,
                failure_reason: "Success rate below rollback threshold".to_string(),
            },
        )
        .expect("canary -> rolled_back");
    manager.save(&record).await.expect("save rollback");

    ctx.log_transition(
        &connector_id,
        &version,
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "auto_rollback",
    );

    // Verify final state
    ctx.assert_eq(
        &record.state,
        &LifecycleState::RolledBack,
        "Should be in RolledBack state",
    );
    ctx.assert_true(!record.state.is_active(), "RolledBack should NOT be active");

    // Verify via manager status
    let status = manager.status(&connector_id).await.expect("get status");
    ctx.assert_eq(
        &status.state,
        &LifecycleState::RolledBack,
        "Manager status should show RolledBack",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Multi-Version Canary with Rollback to Previous
// ─────────────────────────────────────────────────────────────────────────────

/// Test scenario: Deploy v1.0.0 to production, then deploy v1.1.0 as canary.
/// When v1.1.0 canary fails health checks, rollback should occur and
/// the connector can be retried or disabled.
#[fcp_async_core::runtime::test]
#[allow(clippy::too_many_lines)]
async fn test_multi_version_canary_rollback() {
    let mut ctx = E2ETestContext::new("multi_version_canary_rollback");
    let connector_id = test_connector_id();
    let v1 = version_1_0();
    let v2 = version_1_1();

    ctx.log_phase(
        "setup",
        Some(json!({
            "scenario": "multi_version_rollback",
            "connector_id": connector_id.to_string(),
            "v1": v1.to_string(),
            "v2": v2.to_string()
        })),
    );

    let manager = Arc::new(MockLifecycleManager::new());

    // Step 1: Deploy v1.0.0 directly to production (baseline)
    let policy = CanaryPolicy::new()
        .with_promotion_threshold(90)
        .with_rollback_threshold(70)
        .with_min_samples(5)
        .with_min_canary_duration(0);

    let mut record_v1 =
        deploy_to_canary(&manager, connector_id.clone(), v1.clone(), policy.clone()).await;

    // Simulate healthy v1 and promote
    add_health_samples(&mut record_v1, 50, 0);
    record_v1
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect("v1 -> production");
    manager.save(&record_v1).await.expect("save v1 production");

    ctx.log_phase(
        "v1_production",
        Some(json!({
            "version": v1.to_string(),
            "state": "Production",
            "success_rate": record_v1.health.success_rate
        })),
    );

    ctx.assert_eq(
        &record_v1.state,
        &LifecycleState::Production,
        "v1 should be in Production",
    );

    // Step 2: Deploy v1.1.0 as canary (new version)
    let mut record_v2 = LifecycleRecord::new(connector_id.clone(), v2.clone())
        .with_canary_policy(policy)
        .with_previous_version(v1.clone());

    record_v2
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("v2 pending -> installing");
    record_v2
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: v1.to_string(),
                to_version: v2.to_string(),
            },
        )
        .expect("v2 installing -> canary");
    manager.save(&record_v2).await.expect("save v2 canary");

    ctx.log_transition(
        &connector_id,
        &v2,
        LifecycleState::Pending,
        LifecycleState::Canary,
        "new_version_canary",
    );

    // Step 3: v2 canary experiences failures
    add_health_samples(&mut record_v2, 30, 70); // 30% success rate
    manager.save(&record_v2).await.expect("save v2 health");

    ctx.log_connector_state(&connector_id, &v2, record_v2.state, &record_v2.health);

    // Verify v2 should rollback
    ctx.assert_eq(
        &record_v2.health.success_rate,
        &30u8,
        "v2 success rate should be 30%",
    );
    ctx.assert_true(
        record_v2.should_auto_rollback(),
        "v2 should trigger auto-rollback",
    );

    // Step 4: Execute rollback
    record_v2
        .transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: 30,
                failure_reason: "Severe degradation - rolling back to v1.0.0".to_string(),
            },
        )
        .expect("v2 -> rolled_back");
    manager.save(&record_v2).await.expect("save v2 rollback");

    ctx.log_transition(
        &connector_id,
        &v2,
        LifecycleState::Canary,
        LifecycleState::RolledBack,
        "auto_rollback_to_previous",
    );

    // Verify states
    ctx.assert_eq(
        &record_v2.state,
        &LifecycleState::RolledBack,
        "v2 should be RolledBack",
    );

    // Verify previous version is recorded
    ctx.assert_eq(
        &record_v2.previous_version,
        &Some(v1.clone()),
        "Should have previous version recorded",
    );

    // Step 5: Verify audit trail
    ctx.assert_eq(
        &record_v2.transitions.len(),
        &3,
        "v2 should have 3 transitions",
    );

    let last_transition = record_v2.transitions.last().expect("transitions");
    ctx.assert_eq(
        &last_transition.from,
        &LifecycleState::Canary,
        "Last transition from Canary",
    );
    ctx.assert_eq(
        &last_transition.to,
        &LifecycleState::RolledBack,
        "Last transition to RolledBack",
    );

    ctx.log_phase(
        "audit_trail",
        Some(json!({
            "transitions": record_v2.transitions.iter().map(|t| {
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

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Canary in Gray Zone (Neither Promote nor Rollback)
// ─────────────────────────────────────────────────────────────────────────────

/// Test scenario: Canary health is between rollback and promotion thresholds.
/// System should wait for more data before making a decision.
#[fcp_async_core::runtime::test]
async fn test_canary_gray_zone_waits() {
    let mut ctx = E2ETestContext::new("canary_gray_zone_waits");
    let connector_id = test_connector_id();
    let version = version_1_0();

    ctx.log_phase(
        "setup",
        Some(json!({
            "scenario": "gray_zone_decision",
            "connector_id": connector_id.to_string()
        })),
    );

    let manager = Arc::new(MockLifecycleManager::new());

    // Deploy with thresholds that create a gray zone
    let policy = CanaryPolicy::new()
        .with_promotion_threshold(95) // Need 95% to promote
        .with_rollback_threshold(70) // Below 70% triggers rollback
        .with_min_samples(10)
        .with_min_canary_duration(0);

    ctx.log_phase(
        "config",
        Some(json!({
            "promotion_threshold": 95,
            "rollback_threshold": 70,
            "gray_zone": "70-95%"
        })),
    );

    let mut record =
        deploy_to_canary(&manager, connector_id.clone(), version.clone(), policy).await;

    // Simulate traffic in the gray zone (85% success rate)
    add_health_samples(&mut record, 85, 15);
    manager.save(&record).await.expect("save health");

    ctx.log_connector_state(&connector_id, &version, record.state, &record.health);

    // Verify neither action is triggered
    ctx.assert_eq(
        &record.health.success_rate,
        &85u8,
        "Success rate should be 85%",
    );
    ctx.assert_true(
        !record.should_auto_promote(),
        "Should NOT auto-promote at 85%",
    );
    ctx.assert_true(
        !record.should_auto_rollback(),
        "Should NOT auto-rollback at 85%",
    );
    ctx.assert_eq(
        &record.state,
        &LifecycleState::Canary,
        "Should remain in Canary state",
    );

    ctx.log_phase(
        "decision",
        Some(json!({
            "action": "wait",
            "reason": "health in gray zone (70-95%)",
            "current_health": 85
        })),
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Insufficient Samples Delays Decision
// ─────────────────────────────────────────────────────────────────────────────

/// Test scenario: Even with good health, promotion waits for minimum samples.
#[fcp_async_core::runtime::test]
async fn test_insufficient_samples_delays_promotion() {
    let mut ctx = E2ETestContext::new("insufficient_samples_delays_promotion");
    let connector_id = test_connector_id();
    let version = version_1_0();

    ctx.log_phase(
        "setup",
        Some(json!({
            "scenario": "insufficient_samples",
            "connector_id": connector_id.to_string()
        })),
    );

    let manager = Arc::new(MockLifecycleManager::new());

    // Require 100 samples minimum
    let policy = CanaryPolicy::new()
        .with_promotion_threshold(90)
        .with_rollback_threshold(70)
        .with_min_samples(100)
        .with_min_canary_duration(0);

    ctx.log_phase(
        "config",
        Some(json!({
            "min_samples": 100,
            "promotion_threshold": 90
        })),
    );

    let mut record =
        deploy_to_canary(&manager, connector_id.clone(), version.clone(), policy).await;

    // Add only 50 samples (below minimum) with 100% success
    add_health_samples(&mut record, 50, 0);
    manager.save(&record).await.expect("save health");

    ctx.log_connector_state(&connector_id, &version, record.state, &record.health);

    // Verify promotion is blocked by insufficient samples
    ctx.assert_eq(&record.health.samples, &50, "Should have 50 samples");
    ctx.assert_eq(
        &record.health.success_rate,
        &100u8,
        "Success rate should be 100%",
    );
    ctx.assert_true(
        !record.should_auto_promote(),
        "Should NOT promote with insufficient samples",
    );

    ctx.log_phase(
        "decision",
        Some(json!({
            "action": "wait",
            "reason": "insufficient samples",
            "current_samples": 50,
            "required_samples": 100
        })),
    );

    // Add more samples to meet minimum
    add_health_samples(&mut record, 50, 0);
    manager.save(&record).await.expect("save more health");

    ctx.assert_eq(&record.health.samples, &100, "Should have 100 samples");
    ctx.assert_true(
        record.should_auto_promote(),
        "Should auto-promote with sufficient samples",
    );

    ctx.log_phase(
        "decision",
        Some(json!({
            "action": "promote",
            "reason": "samples requirement met",
            "current_samples": 100
        })),
    );

    ctx.finalize("pass");
}
