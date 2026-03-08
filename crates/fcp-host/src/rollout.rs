//! Host-side rollout control for staged connector deployments.
//!
//! This module bridges the generic lifecycle primitives in `fcp-core` with
//! host-observed health signals:
//! - registry self-check results
//! - connector availability/degradation status
//! - success/error-rate samples from live traffic
//! - process uptime and crash-loop detection
//!
//! The controller persists lifecycle state through the provided
//! [`fcp_core::LifecycleManager`] and emits deterministic evidence bundles for
//! each scheduling/evaluation decision.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use blake3::hash;
use chrono::{DateTime, Utc};
use fcp_core::{
    CanaryPolicy, ConnectorHealth, ConnectorId, CrashLoopDetector, LifecycleError,
    LifecycleManager, LifecycleRecord, LifecycleState, RolloutPolicy, SelfCheckReport,
    SelfCheckStatus, TransitionReason,
};
use serde::{Deserialize, Serialize};

use crate::{ConnectorRegistry, HostError, HostResult};

/// Configuration for rollout-controller health gating.
#[derive(Debug, Clone)]
pub struct RolloutControllerConfig {
    /// Minimum supervisor-observed uptime before auto-promotion is allowed.
    pub min_uptime_secs_for_promotion: u64,
    /// Whether connectors that do not implement self-check may still auto-promote.
    pub allow_unsupported_self_check_promotion: bool,
    /// Crash-loop threshold used by the host-side detector.
    pub crash_loop_threshold: usize,
    /// Crash-loop evaluation window in seconds.
    pub crash_loop_window_secs: i64,
}

impl Default for RolloutControllerConfig {
    fn default() -> Self {
        Self {
            min_uptime_secs_for_promotion: 60,
            allow_unsupported_self_check_promotion: true,
            crash_loop_threshold: 3,
            crash_loop_window_secs: 300,
        }
    }
}

/// Supervisor observation used to evaluate a rollout step.
#[derive(Debug, Clone)]
pub struct RolloutObservation {
    /// Whether the most recent invocation or health sample succeeded.
    pub invocation_succeeded: bool,
    /// Optional end-to-end latency for the sample.
    pub latency_ms: Option<u32>,
    /// Supervisor-observed connector uptime.
    pub uptime_secs: u64,
    /// Whether the deployment is pinned and therefore must not auto-promote.
    pub pinned: bool,
    /// Whether the supervisor observed a hard crash for this connector.
    pub crashed: bool,
    /// Rollout policy to evaluate against.
    pub policy: RolloutPolicy,
    /// Timestamp associated with the observation.
    pub observed_at: DateTime<Utc>,
}

impl RolloutObservation {
    /// Create a new observation using the current wall-clock time.
    #[must_use]
    pub fn new(invocation_succeeded: bool, policy: RolloutPolicy) -> Self {
        Self {
            invocation_succeeded,
            latency_ms: None,
            uptime_secs: 0,
            pinned: false,
            crashed: false,
            policy,
            observed_at: Utc::now(),
        }
    }

    /// Set the observed latency in milliseconds.
    #[must_use]
    pub const fn with_latency_ms(mut self, latency_ms: u32) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Set the observed uptime in seconds.
    #[must_use]
    pub const fn with_uptime_secs(mut self, uptime_secs: u64) -> Self {
        self.uptime_secs = uptime_secs;
        self
    }

    /// Mark the deployment as pinned.
    #[must_use]
    pub const fn pinned(mut self, pinned: bool) -> Self {
        self.pinned = pinned;
        self
    }

    /// Mark the observation as a crash signal.
    #[must_use]
    pub const fn crashed(mut self, crashed: bool) -> Self {
        self.crashed = crashed;
        self
    }

    /// Override the observation timestamp.
    #[must_use]
    pub const fn observed_at(mut self, observed_at: DateTime<Utc>) -> Self {
        self.observed_at = observed_at;
        self
    }
}

/// High-level rollout decision taken by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutDecision {
    /// A connector was scheduled or re-entered into canary.
    Scheduled,
    /// No state transition occurred.
    Hold,
    /// Canary was promoted to production.
    Promote,
    /// Canary was rolled back.
    Rollback,
}

impl RolloutDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Hold => "hold",
            Self::Promote => "promote",
            Self::Rollback => "rollback",
        }
    }
}

/// Deterministic audit record for a rollout decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutAuditEvent {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// State before evaluation.
    pub state_before: LifecycleState,
    /// State after evaluation.
    pub state_after: LifecycleState,
    /// Controller decision.
    pub decision: RolloutDecision,
    /// Stable reason code for the decision.
    pub reason_code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Timestamp at which the decision was made.
    pub observed_at: DateTime<Utc>,
    /// Content digest of the evidence bundle.
    pub evidence_digest: String,
}

/// Evidence bundle used for audit and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutEvidence {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// State before evaluation.
    pub state_before: LifecycleState,
    /// State after evaluation.
    pub state_after: LifecycleState,
    /// Current controller decision.
    pub decision: RolloutDecision,
    /// Stable reason code.
    pub reason_code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Whether the deployment is pinned.
    pub pinned: bool,
    /// Whether a crash loop was detected.
    pub crash_loop_detected: bool,
    /// Current consecutive failure streak tracked by the host.
    pub failure_streak: u32,
    /// Latest self-check status.
    pub self_check_status: SelfCheckStatus,
    /// Stable self-check reason code, when present.
    pub self_check_reason_code: Option<String>,
    /// Current external connector-health status.
    pub connector_health_status: String,
    /// Optional external connector-health reason.
    pub connector_health_reason: Option<String>,
    /// Samples recorded in lifecycle health.
    pub samples: u64,
    /// Success rate in basis points.
    pub success_rate_bps: u16,
    /// Error rate in basis points.
    pub error_rate_bps: u16,
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<u32>,
    /// Maximum observed latency in milliseconds.
    pub max_latency_ms: u32,
    /// Supervisor-observed uptime in seconds.
    pub uptime_secs: u64,
    /// Elapsed canary duration in seconds, if in canary.
    pub canary_elapsed_secs: Option<u64>,
    /// Remaining canary duration before expiry, if in canary.
    pub canary_expires_in_secs: Option<u32>,
    /// Promotion success-rate threshold in basis points.
    pub promotion_threshold_bps: u16,
    /// Promotion max-error threshold in basis points.
    pub promotion_max_error_bps: u16,
    /// Promotion minimum samples.
    pub promotion_min_samples: u32,
    /// Rollback max-error threshold in basis points.
    pub rollback_max_error_bps: u16,
    /// Rollback failure-streak threshold.
    pub rollback_max_consecutive_failures: u32,
    /// Rollback minimum samples.
    pub rollback_min_samples: u32,
    /// Whether the rollout policy allows automatic rollback.
    pub auto_rollback: bool,
    /// Evaluation timestamp.
    pub observed_at: DateTime<Utc>,
}

impl RolloutEvidence {
    /// Compute a stable digest for the evidence bundle.
    ///
    /// # Panics
    ///
    /// Panics if evidence serialization fails (should never occur with
    /// well-formed evidence).
    #[must_use]
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self)
            .expect("rollout evidence serialization should be deterministic");
        format!("blake3-256:{}", hash(&bytes).to_hex())
    }
}

/// Result of a rollout scheduling or evaluation step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutOutcome {
    /// Updated lifecycle record after persistence.
    pub record: LifecycleRecord,
    /// High-level controller decision.
    pub decision: RolloutDecision,
    /// Audit event describing the decision.
    pub audit_event: RolloutAuditEvent,
    /// Evidence bundle backing the audit event.
    pub evidence: RolloutEvidence,
}

/// Host-side controller that evaluates canary promotion/rollback decisions.
pub struct RolloutController<R, M> {
    registry: Arc<R>,
    lifecycle: Arc<M>,
    config: RolloutControllerConfig,
    state: Mutex<HashMap<ConnectorId, ConnectorRuntimeState>>,
}

impl<R, M> RolloutController<R, M>
where
    R: ConnectorRegistry,
    M: LifecycleManager,
{
    /// Create a new rollout controller with default configuration.
    #[must_use]
    pub fn new(registry: Arc<R>, lifecycle: Arc<M>) -> Self {
        Self::with_config(registry, lifecycle, RolloutControllerConfig::default())
    }

    /// Create a new rollout controller with explicit configuration.
    #[must_use]
    pub fn with_config(
        registry: Arc<R>,
        lifecycle: Arc<M>,
        config: RolloutControllerConfig,
    ) -> Self {
        Self {
            registry,
            lifecycle,
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Start or re-enter a connector rollout in canary mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is missing, the policy is invalid, or
    /// lifecycle persistence fails.
    #[allow(clippy::too_many_lines)]
    pub async fn schedule_canary(
        &self,
        connector_id: &ConnectorId,
        version: semver::Version,
        previous_version: Option<semver::Version>,
        policy: &RolloutPolicy,
        observed_at: DateTime<Utc>,
    ) -> HostResult<RolloutOutcome> {
        policy
            .validate()
            .map_err(|error| HostError::Internal(format!("invalid rollout policy: {error}")))?;

        let _summary = self
            .registry
            .get(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        let mut record = self
            .get_record(connector_id)
            .await?
            .unwrap_or_else(|| LifecycleRecord::new(connector_id.clone(), version.clone()));

        let state_before = record.state;
        let previous_recorded_version = record.version.clone();
        if previous_version.is_some() {
            record.previous_version = previous_version;
        } else if previous_recorded_version != version {
            record.previous_version = Some(previous_recorded_version.clone());
        }
        record.version = version.clone();
        record.canary_policy = to_canary_policy(policy);
        record.reset_health();

        transition_to_canary(
            &mut record,
            connector_id,
            &version,
            previous_recorded_version,
            observed_at,
        )?;

        self.lifecycle
            .save(&record)
            .await
            .map_err(map_lifecycle_error)?;
        self.reset_runtime_state(connector_id);

        let evidence = build_evidence(&BuildEvidenceInput {
            record: &record,
            state_before,
            decision: RolloutDecision::Scheduled,
            reason_code: "canary_scheduled",
            message: "connector scheduled in canary",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::unsupported(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 0,
            policy,
            observed_at,
        });
        let audit_event = build_audit_event(
            connector_id,
            state_before,
            record.state,
            RolloutDecision::Scheduled,
            &evidence,
        );

        tracing::info!(
            connector_id = %connector_id,
            decision = %RolloutDecision::Scheduled.as_str(),
            state_before = %state_before,
            state_after = %record.state,
            evidence_digest = %audit_event.evidence_digest,
            "rollout decision"
        );

        Ok(RolloutOutcome {
            record,
            decision: RolloutDecision::Scheduled,
            audit_event,
            evidence,
        })
    }

    /// Evaluate a single rollout observation and persist any transition.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is unknown, the rollout policy is
    /// invalid, or the lifecycle manager rejects the transition/persistence.
    #[allow(clippy::too_many_lines)]
    pub async fn evaluate(
        &self,
        connector_id: &ConnectorId,
        observation: RolloutObservation,
    ) -> HostResult<RolloutOutcome> {
        observation
            .policy
            .validate()
            .map_err(|error| HostError::Internal(format!("invalid rollout policy: {error}")))?;

        let summary = self
            .registry
            .get(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        let self_check = self
            .registry
            .self_check(connector_id)
            .await
            .unwrap_or_else(SelfCheckReport::unsupported);

        let mut record = self
            .get_record(connector_id)
            .await?
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        record.canary_policy = to_canary_policy(&observation.policy);
        record.update_health(observation.invocation_succeeded, observation.latency_ms);

        let runtime_state = self.update_runtime_state(connector_id, &observation);
        let state_before = record.state;
        let decision_plan = evaluate_decision(
            &record,
            &summary.health,
            &self_check,
            runtime_state.failure_streak,
            runtime_state.crash_loop_detected,
            &observation,
            &self.config,
        );

        let decision = match decision_plan.decision {
            RolloutDecision::Promote => {
                record
                    .transition(
                        LifecycleState::Production,
                        TransitionReason::AutoPromotion {
                            health_score: health_score_percent(record.health.success_rate),
                        },
                    )
                    .map_err(map_lifecycle_error)?;
                RolloutDecision::Promote
            }
            RolloutDecision::Rollback => {
                if record.previous_version.is_none() {
                    return Err(map_lifecycle_error(LifecycleError::NoRollbackTarget));
                }
                record
                    .transition(
                        LifecycleState::RolledBack,
                        TransitionReason::AutoRollback {
                            health_score: health_score_percent(record.health.success_rate),
                            failure_reason: decision_plan.message.clone(),
                        },
                    )
                    .map_err(map_lifecycle_error)?;
                RolloutDecision::Rollback
            }
            RolloutDecision::Hold => RolloutDecision::Hold,
            RolloutDecision::Scheduled => RolloutDecision::Scheduled,
        };

        self.lifecycle
            .save(&record)
            .await
            .map_err(map_lifecycle_error)?;

        let evidence = build_evidence(&BuildEvidenceInput {
            record: &record,
            state_before,
            decision,
            reason_code: decision_plan.reason_code,
            message: &decision_plan.message,
            pinned: observation.pinned,
            crash_loop_detected: runtime_state.crash_loop_detected,
            failure_streak: runtime_state.failure_streak,
            self_check: &self_check,
            connector_health: &summary.health,
            uptime_secs: observation.uptime_secs,
            policy: &observation.policy,
            observed_at: observation.observed_at,
        });
        let audit_event = build_audit_event(
            connector_id,
            state_before,
            record.state,
            decision,
            &evidence,
        );

        tracing::info!(
            connector_id = %connector_id,
            decision = %decision.as_str(),
            state_before = %state_before,
            state_after = %record.state,
            success_rate_bps = evidence.success_rate_bps,
            error_rate_bps = evidence.error_rate_bps,
            failure_streak = evidence.failure_streak,
            crash_loop_detected = evidence.crash_loop_detected,
            evidence_digest = %audit_event.evidence_digest,
            "rollout decision"
        );

        Ok(RolloutOutcome {
            record,
            decision,
            audit_event,
            evidence,
        })
    }

    async fn get_record(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, HostError> {
        self.lifecycle
            .get(connector_id)
            .await
            .map_err(map_lifecycle_error)
    }

    #[allow(clippy::significant_drop_tightening)]
    fn update_runtime_state(
        &self,
        connector_id: &ConnectorId,
        observation: &RolloutObservation,
    ) -> RuntimeSnapshot {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry =
                state
                    .entry(connector_id.clone())
                    .or_insert_with(|| ConnectorRuntimeState {
                        failure_streak: 0,
                        crash_detector: CrashLoopDetector::new(
                            self.config.crash_loop_threshold,
                            self.config.crash_loop_window_secs,
                        ),
                    });

            if observation.invocation_succeeded {
                entry.failure_streak = 0;
                entry.crash_detector.record_success();
            } else {
                entry.failure_streak = entry.failure_streak.saturating_add(1);
                if observation.crashed {
                    entry.crash_detector.record_crash(observation.observed_at);
                }
            }

            RuntimeSnapshot {
                failure_streak: entry.failure_streak,
                crash_loop_detected: observation.crashed
                    && entry.crash_detector.is_crash_loop(observation.observed_at),
            }
        }
    }

    fn reset_runtime_state(&self, connector_id: &ConnectorId) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(connector_id);
    }
}

#[derive(Debug, Clone)]
struct ConnectorRuntimeState {
    failure_streak: u32,
    crash_detector: CrashLoopDetector,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeSnapshot {
    failure_streak: u32,
    crash_loop_detected: bool,
}

#[derive(Debug, Clone)]
struct DecisionPlan {
    decision: RolloutDecision,
    reason_code: &'static str,
    message: String,
}

fn transition_to_canary(
    record: &mut LifecycleRecord,
    connector_id: &ConnectorId,
    version: &semver::Version,
    previous_recorded_version: semver::Version,
    observed_at: DateTime<Utc>,
) -> HostResult<()> {
    match record.state {
        LifecycleState::Pending => {
            record
                .transition(
                    LifecycleState::Installing,
                    TransitionReason::InstallComplete,
                )
                .map_err(map_lifecycle_error)?;
            record
                .transition(LifecycleState::Canary, canary_reason(None, version))
                .map_err(map_lifecycle_error)?;
        }
        LifecycleState::Installing => {
            record
                .transition(LifecycleState::Canary, canary_reason(None, version))
                .map_err(map_lifecycle_error)?;
        }
        LifecycleState::Production | LifecycleState::RolledBack | LifecycleState::Disabled => {
            let reason =
                (previous_recorded_version != *version).then_some(previous_recorded_version);
            record
                .transition(
                    LifecycleState::Canary,
                    canary_reason(reason.as_ref(), version),
                )
                .map_err(map_lifecycle_error)?;
        }
        LifecycleState::Canary => {
            record.state_changed_at = observed_at;
            if let Some(last_transition) = record.transitions.last_mut() {
                last_transition.timestamp = observed_at;
            }
        }
        LifecycleState::Uninstalled => {
            return Err(HostError::Unavailable(format!(
                "cannot schedule canary for uninstalled connector {connector_id}"
            )));
        }
    }
    record.state_changed_at = observed_at;
    if let Some(last_transition) = record.transitions.last_mut() {
        last_transition.timestamp = observed_at;
    }
    Ok(())
}

fn evaluate_decision(
    record: &LifecycleRecord,
    connector_health: &ConnectorHealth,
    self_check: &SelfCheckReport,
    failure_streak: u32,
    crash_loop_detected: bool,
    observation: &RolloutObservation,
    config: &RolloutControllerConfig,
) -> DecisionPlan {
    if record.state != LifecycleState::Canary {
        return DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "state_not_canary",
            message: format!("connector is in {} state", record.state),
        };
    }

    if let Some(plan) = check_rollback_conditions(
        record,
        connector_health,
        self_check,
        failure_streak,
        crash_loop_detected,
        observation,
    ) {
        return plan;
    }

    if let Some(plan) =
        check_hold_conditions(record, connector_health, self_check, observation, config)
    {
        return plan;
    }

    let error_rate_bps = error_rate_bps(record);
    let success_rate_bps = success_rate_bps(record);
    if success_rate_bps >= observation.policy.success_thresholds.min_success_rate_bps
        && error_rate_bps <= observation.policy.success_thresholds.max_error_rate_bps
    {
        return DecisionPlan {
            decision: RolloutDecision::Promote,
            reason_code: "promotion_thresholds_met",
            message: "canary met promotion success thresholds".to_string(),
        };
    }

    DecisionPlan {
        decision: RolloutDecision::Hold,
        reason_code: "promotion_thresholds_not_met",
        message: format!(
            "success rate {success_rate_bps}bps / error rate {error_rate_bps}bps did not satisfy promotion thresholds"
        ),
    }
}

fn check_rollback_conditions(
    record: &LifecycleRecord,
    connector_health: &ConnectorHealth,
    self_check: &SelfCheckReport,
    failure_streak: u32,
    crash_loop_detected: bool,
    observation: &RolloutObservation,
) -> Option<DecisionPlan> {
    if matches!(self_check.status, SelfCheckStatus::Failed) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "self_check_failed",
            message: explain_self_check(self_check),
        });
    }

    if matches!(connector_health, ConnectorHealth::Unavailable { .. }) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "connector_unavailable",
            message: connector_health_reason(connector_health)
                .unwrap_or_else(|| "connector became unavailable".to_string()),
        });
    }

    if crash_loop_detected {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "crash_loop_detected",
            message: "connector entered a crash loop during canary".to_string(),
        });
    }

    let error_rate_bps = error_rate_bps(record);
    let rules = &observation.policy.rollback_rules;
    if rules.auto_rollback
        && record.health.samples >= u64::from(rules.min_samples)
        && failure_streak >= rules.max_consecutive_failures
    {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "consecutive_failures_exceeded",
            message: format!(
                "failure streak {failure_streak} exceeded rollout limit {}",
                rules.max_consecutive_failures
            ),
        });
    }

    if rules.auto_rollback
        && record.health.samples >= u64::from(rules.min_samples)
        && error_rate_bps > rules.max_error_rate_bps
    {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "error_rate_exceeded",
            message: format!(
                "error rate {error_rate_bps}bps exceeded rollout limit {}bps",
                rules.max_error_rate_bps
            ),
        });
    }

    if record.canary_expires_in_secs_at(observation.observed_at) == Some(0) && rules.auto_rollback {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "canary_expired",
            message: "canary window expired before promotion thresholds were met".to_string(),
        });
    }

    None
}

fn check_hold_conditions(
    record: &LifecycleRecord,
    connector_health: &ConnectorHealth,
    self_check: &SelfCheckReport,
    observation: &RolloutObservation,
    config: &RolloutControllerConfig,
) -> Option<DecisionPlan> {
    if observation.pinned {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "pinned",
            message: "connector is pinned, auto-promotion is disabled".to_string(),
        });
    }

    if matches!(self_check.status, SelfCheckStatus::Degraded) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "self_check_degraded",
            message: explain_self_check(self_check),
        });
    }

    if matches!(connector_health, ConnectorHealth::Degraded { .. }) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "connector_degraded",
            message: connector_health_reason(connector_health)
                .unwrap_or_else(|| "connector is degraded".to_string()),
        });
    }

    if matches!(self_check.status, SelfCheckStatus::Unsupported)
        && !config.allow_unsupported_self_check_promotion
    {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "self_check_required",
            message: "self-check support is required before promotion".to_string(),
        });
    }

    if observation.uptime_secs < config.min_uptime_secs_for_promotion {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "uptime_too_low",
            message: format!(
                "uptime {}s is below promotion floor {}s",
                observation.uptime_secs, config.min_uptime_secs_for_promotion
            ),
        });
    }

    let canary_elapsed = canary_elapsed_secs(record, observation.observed_at).unwrap_or(0);
    if canary_elapsed < u64::from(observation.policy.min_canary_duration_secs) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "canary_duration_not_met",
            message: format!(
                "canary has only run for {canary_elapsed}s (minimum {}s)",
                observation.policy.min_canary_duration_secs
            ),
        });
    }

    if record.health.samples < u64::from(observation.policy.success_thresholds.min_samples) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "insufficient_samples",
            message: format!(
                "only {} samples collected (need at least {})",
                record.health.samples, observation.policy.success_thresholds.min_samples
            ),
        });
    }

    None
}

struct BuildEvidenceInput<'a> {
    record: &'a LifecycleRecord,
    state_before: LifecycleState,
    decision: RolloutDecision,
    reason_code: &'a str,
    message: &'a str,
    pinned: bool,
    crash_loop_detected: bool,
    failure_streak: u32,
    self_check: &'a SelfCheckReport,
    connector_health: &'a ConnectorHealth,
    uptime_secs: u64,
    policy: &'a RolloutPolicy,
    observed_at: DateTime<Utc>,
}

fn build_evidence(input: &BuildEvidenceInput<'_>) -> RolloutEvidence {
    let (connector_health_status, connector_health_reason) =
        connector_health_fields(input.connector_health);

    RolloutEvidence {
        connector_id: input.record.connector_id.clone(),
        state_before: input.state_before,
        state_after: input.record.state,
        decision: input.decision,
        reason_code: input.reason_code.to_string(),
        message: input.message.to_string(),
        pinned: input.pinned,
        crash_loop_detected: input.crash_loop_detected,
        failure_streak: input.failure_streak,
        self_check_status: input.self_check.status,
        self_check_reason_code: input.self_check.reason_code.clone(),
        connector_health_status,
        connector_health_reason,
        samples: input.record.health.samples,
        success_rate_bps: success_rate_bps(input.record),
        error_rate_bps: error_rate_bps(input.record),
        avg_latency_ms: input.record.health.avg_latency_ms(),
        max_latency_ms: input.record.health.max_latency_ms,
        uptime_secs: input.uptime_secs,
        canary_elapsed_secs: canary_elapsed_secs(input.record, input.observed_at),
        canary_expires_in_secs: input.record.canary_expires_in_secs_at(input.observed_at),
        promotion_threshold_bps: input.policy.success_thresholds.min_success_rate_bps,
        promotion_max_error_bps: input.policy.success_thresholds.max_error_rate_bps,
        promotion_min_samples: input.policy.success_thresholds.min_samples,
        rollback_max_error_bps: input.policy.rollback_rules.max_error_rate_bps,
        rollback_max_consecutive_failures: input.policy.rollback_rules.max_consecutive_failures,
        rollback_min_samples: input.policy.rollback_rules.min_samples,
        auto_rollback: input.policy.rollback_rules.auto_rollback,
        observed_at: input.observed_at,
    }
}

fn build_audit_event(
    connector_id: &ConnectorId,
    state_before: LifecycleState,
    state_after: LifecycleState,
    decision: RolloutDecision,
    evidence: &RolloutEvidence,
) -> RolloutAuditEvent {
    RolloutAuditEvent {
        connector_id: connector_id.clone(),
        state_before,
        state_after,
        decision,
        reason_code: evidence.reason_code.clone(),
        message: evidence.message.clone(),
        observed_at: evidence.observed_at,
        evidence_digest: evidence.digest(),
    }
}

fn canary_reason(
    previous_version: Option<&semver::Version>,
    version: &semver::Version,
) -> TransitionReason {
    previous_version.map_or(TransitionReason::InstallComplete, |prev| {
        TransitionReason::NewVersion {
            from_version: prev.to_string(),
            to_version: version.to_string(),
        }
    })
}

fn to_canary_policy(policy: &RolloutPolicy) -> CanaryPolicy {
    CanaryPolicy {
        promotion_threshold: percent_from_bps_ceil(policy.success_thresholds.min_success_rate_bps),
        rollback_threshold: 100u8.saturating_sub(percent_from_bps_ceil(
            policy.rollback_rules.max_error_rate_bps,
        )),
        min_samples: u64::from(policy.success_thresholds.min_samples),
        min_canary_duration_secs: policy.min_canary_duration_secs,
        max_canary_duration_secs: policy
            .min_canary_duration_secs
            .max(policy.success_thresholds.window_secs)
            .max(policy.rollback_rules.window_secs),
        canary_traffic_percent: policy.canary_percent,
    }
}

fn percent_from_bps_ceil(bps: u16) -> u8 {
    let percent = bps.min(10_000).div_ceil(100);
    u8::try_from(percent).unwrap_or(100)
}

fn success_rate_bps(record: &LifecycleRecord) -> u16 {
    if record.health.samples == 0 {
        return 10_000;
    }
    let numerator = record.health.successes.saturating_mul(10_000);
    let rate = numerator / record.health.samples;
    u16::try_from(rate.min(10_000)).unwrap_or(10_000)
}

fn error_rate_bps(record: &LifecycleRecord) -> u16 {
    if record.health.samples == 0 {
        return 0;
    }
    let numerator = record.health.failures.saturating_mul(10_000);
    let rate = numerator / record.health.samples;
    u16::try_from(rate.min(10_000)).unwrap_or(10_000)
}

fn health_score_percent(percent: u8) -> u8 {
    percent.min(100)
}

fn canary_elapsed_secs(record: &LifecycleRecord, now: DateTime<Utc>) -> Option<u64> {
    if record.state != LifecycleState::Canary {
        return None;
    }

    let start = record
        .transitions
        .iter()
        .rev()
        .find(|transition| transition.to == LifecycleState::Canary)
        .map_or(record.deployed_at, |transition| transition.timestamp);
    let elapsed = now.signed_duration_since(start).num_seconds().max(0);
    u64::try_from(elapsed).ok()
}

fn connector_health_fields(health: &ConnectorHealth) -> (String, Option<String>) {
    match health {
        ConnectorHealth::Healthy => ("healthy".to_string(), None),
        ConnectorHealth::Degraded { reason } => ("degraded".to_string(), Some(reason.clone())),
        ConnectorHealth::Unavailable { reason, .. } => {
            ("unavailable".to_string(), Some(reason.clone()))
        }
    }
}

fn connector_health_reason(health: &ConnectorHealth) -> Option<String> {
    connector_health_fields(health).1
}

fn explain_self_check(self_check: &SelfCheckReport) -> String {
    self_check
        .message
        .clone()
        .or_else(|| self_check.reason_code.clone())
        .unwrap_or_else(|| {
            format!(
                "self-check returned {}",
                self_check_status_label(self_check)
            )
        })
}

const fn self_check_status_label(self_check: &SelfCheckReport) -> &'static str {
    match self_check.status {
        SelfCheckStatus::Ok => "ok",
        SelfCheckStatus::Degraded => "degraded",
        SelfCheckStatus::Failed => "failed",
        SelfCheckStatus::Unsupported => "unsupported",
    }
}

fn map_lifecycle_error(error: LifecycleError) -> HostError {
    match error {
        LifecycleError::NotFound { connector_id } => {
            HostError::ConnectorNotFound(connector_id.to_string())
        }
        other => HostError::Internal(format!("lifecycle error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use fcp_async_core::sync::RwLock;
    use fcp_core::{
        AgentHint, ApprovalMode, CapabilityId, IdempotencyClass, Introspection, LifecycleStatus,
        OperationId, OperationInfo, RateLimitDeclarations, RiskLevel, SafetyTier,
    };

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test.rollout:utility:1.0.0")
    }

    fn rollout_policy() -> RolloutPolicy {
        RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(120)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 300, true))
            .build()
    }

    fn operation(id: &str) -> OperationInfo {
        OperationInfo {
            id: OperationId::new(id).expect("valid operation id"),
            summary: id.to_string(),
            description: Some(format!("{id} operation")),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: serde_json::json!({"type":"object"}),
            capability: CapabilityId::new(format!("cap.{id}")).expect("valid cap"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: id.to_string(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        }
    }

    fn connector_summary(health: ConnectorHealth) -> crate::ConnectorSummary {
        crate::ConnectorSummary {
            id: connector_id(),
            name: "rollout-test".to_string(),
            description: Some("rollout test connector".to_string()),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: 1,
            max_safety_tier: SafetyTier::Safe,
            enabled: true,
            health,
            last_health_check: Some(Utc::now()),
        }
    }

    fn introspection() -> Introspection {
        Introspection {
            operations: vec![operation("echo")],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    struct TestRegistry {
        summary: crate::ConnectorSummary,
        self_check: SelfCheckReport,
    }

    #[async_trait]
    impl ConnectorRegistry for TestRegistry {
        async fn list(&self) -> Vec<crate::ConnectorSummary> {
            vec![self.summary.clone()]
        }

        async fn get(&self, id: &ConnectorId) -> Option<crate::ConnectorSummary> {
            (&self.summary.id == id).then(|| self.summary.clone())
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            (&self.summary.id == id).then(introspection)
        }

        async fn get_archetype(&self, id: &ConnectorId) -> Option<crate::ConnectorArchetype> {
            (&self.summary.id == id).then_some(crate::ConnectorArchetype::RequestResponse)
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            (&self.summary.id == id).then(|| self.self_check.clone())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    struct InMemoryLifecycleManager {
        records: RwLock<HashMap<ConnectorId, LifecycleRecord>>,
    }

    impl InMemoryLifecycleManager {
        fn new() -> Self {
            Self {
                records: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl LifecycleManager for InMemoryLifecycleManager {
        async fn get(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<Option<LifecycleRecord>, LifecycleError> {
            Ok(self.records.read().await.get(connector_id).cloned())
        }

        async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError> {
            self.records
                .write()
                .await
                .insert(record.connector_id.clone(), record.clone());
            Ok(())
        }

        async fn promote(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<LifecycleRecord, LifecycleError> {
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
            Ok(record.clone())
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
            Ok(record.clone())
        }

        async fn status(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<LifecycleStatus, LifecycleError> {
            let records = self.records.read().await;
            let record = records
                .get(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
            Ok(LifecycleStatus::from_record(record, Utc::now(), false))
        }
    }

    async fn scheduled_record(
        registry: Arc<TestRegistry>,
        lifecycle: Arc<InMemoryLifecycleManager>,
        observed_at: DateTime<Utc>,
    ) -> RolloutController<TestRegistry, InMemoryLifecycleManager> {
        let controller = RolloutController::with_config(
            registry,
            lifecycle.clone(),
            RolloutControllerConfig {
                min_uptime_secs_for_promotion: 30,
                ..RolloutControllerConfig::default()
            },
        );

        controller
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                observed_at,
            )
            .await
            .expect("canary should schedule");
        controller
    }

    #[fcp_async_core::runtime::test]
    async fn schedule_canary_transitions_to_canary() {
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = RolloutController::new(registry, lifecycle.clone());
        let observed_at = Utc::now();

        let outcome = controller
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                observed_at,
            )
            .await
            .expect("schedule should succeed");

        assert_eq!(outcome.decision, RolloutDecision::Scheduled);
        assert_eq!(outcome.record.state, LifecycleState::Canary);
        assert_eq!(
            outcome.record.previous_version,
            Some(semver::Version::new(1, 0, 0))
        );
        assert_eq!(outcome.audit_event.reason_code, "canary_scheduled");
    }

    #[fcp_async_core::runtime::test]
    async fn healthy_canary_promotes_to_production() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle, observed_at).await;

        for _ in 0..4 {
            let _ = controller
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(true, rollout_policy())
                        .with_latency_ms(25)
                        .with_uptime_secs(180)
                        .observed_at(Utc::now()),
                )
                .await
                .expect("evaluation should succeed");
        }

        let outcome = controller
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_latency_ms(30)
                    .with_uptime_secs(181)
                    .observed_at(Utc::now()),
            )
            .await
            .expect("final evaluation should succeed");

        assert_eq!(outcome.decision, RolloutDecision::Promote);
        assert_eq!(outcome.record.state, LifecycleState::Production);
        assert_eq!(outcome.audit_event.reason_code, "promotion_thresholds_met");
    }

    #[fcp_async_core::runtime::test]
    async fn pinned_canary_never_auto_promotes() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle, observed_at).await;

        for _ in 0..6 {
            let outcome = controller
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(true, rollout_policy())
                        .with_latency_ms(15)
                        .with_uptime_secs(200)
                        .pinned(true)
                        .observed_at(Utc::now()),
                )
                .await
                .expect("evaluation should succeed");
            assert_eq!(outcome.decision, RolloutDecision::Hold);
            assert_eq!(outcome.audit_event.reason_code, "pinned");
            assert_eq!(outcome.record.state, LifecycleState::Canary);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn failed_self_check_triggers_rollback() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::failed("self_check_failed", "database unavailable"),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle, observed_at).await;

        let outcome = controller
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_latency_ms(250)
                    .with_uptime_secs(180)
                    .observed_at(Utc::now()),
            )
            .await
            .expect("rollback evaluation should succeed");

        assert_eq!(outcome.decision, RolloutDecision::Rollback);
        assert_eq!(outcome.record.state, LifecycleState::RolledBack);
        assert_eq!(outcome.audit_event.reason_code, "self_check_failed");
    }

    #[fcp_async_core::runtime::test]
    async fn failure_streak_triggers_rollback() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle, observed_at).await;

        let mut last = None;
        for _ in 0..3 {
            last = Some(
                controller
                    .evaluate(
                        &connector_id(),
                        RolloutObservation::new(false, rollout_policy())
                            .with_latency_ms(500)
                            .with_uptime_secs(180)
                            .observed_at(Utc::now()),
                    )
                    .await
                    .expect("evaluation should succeed"),
            );
        }

        let outcome = last.expect("last outcome");
        assert_eq!(outcome.decision, RolloutDecision::Rollback);
        assert_eq!(outcome.record.state, LifecycleState::RolledBack);
        assert_eq!(
            outcome.audit_event.reason_code,
            "consecutive_failures_exceeded"
        );
    }

    #[test]
    fn evidence_digest_is_deterministic() {
        let mut record = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .expect("installing -> canary");

        let evidence_a = build_evidence(&BuildEvidenceInput {
            record: &record,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "insufficient_samples",
            message: "need more samples",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 90,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let evidence_b = evidence_a.clone();

        assert_eq!(evidence_a.digest(), evidence_b.digest());
    }

    #[test]
    fn default_config_values() {
        let c = RolloutControllerConfig::default();
        assert_eq!(c.min_uptime_secs_for_promotion, 60);
        assert!(c.allow_unsupported_self_check_promotion);
        assert_eq!(c.crash_loop_threshold, 3);
        assert_eq!(c.crash_loop_window_secs, 300);
    }

    #[test]
    fn config_clone_eq() {
        let c = RolloutControllerConfig {
            min_uptime_secs_for_promotion: 120,
            allow_unsupported_self_check_promotion: false,
            crash_loop_threshold: 5,
            crash_loop_window_secs: 600,
        };
        let d = c.clone();
        assert_eq!(
            c.min_uptime_secs_for_promotion,
            d.min_uptime_secs_for_promotion
        );
        assert_eq!(c.crash_loop_threshold, d.crash_loop_threshold);
    }

    #[test]
    fn observation_defaults() {
        let o = RolloutObservation::new(true, rollout_policy());
        assert!(o.invocation_succeeded);
        assert!(o.latency_ms.is_none());
        assert_eq!(o.uptime_secs, 0);
        assert!(!o.pinned);
        assert!(!o.crashed);
    }

    #[test]
    fn observation_builder() {
        let now = Utc::now();
        let o = RolloutObservation::new(false, rollout_policy())
            .with_latency_ms(42)
            .with_uptime_secs(100)
            .pinned(true)
            .crashed(true)
            .observed_at(now);
        assert_eq!(o.latency_ms, Some(42));
        assert_eq!(o.uptime_secs, 100);
        assert!(o.pinned);
        assert!(o.crashed);
        assert_eq!(o.observed_at, now);
    }

    #[test]
    fn decision_as_str_all() {
        assert_eq!(RolloutDecision::Scheduled.as_str(), "scheduled");
        assert_eq!(RolloutDecision::Hold.as_str(), "hold");
        assert_eq!(RolloutDecision::Promote.as_str(), "promote");
        assert_eq!(RolloutDecision::Rollback.as_str(), "rollback");
    }

    #[test]
    fn decision_serde() {
        for d in [
            RolloutDecision::Scheduled,
            RolloutDecision::Hold,
            RolloutDecision::Promote,
            RolloutDecision::Rollback,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            assert_eq!(d, serde_json::from_str::<RolloutDecision>(&j).unwrap());
        }
    }

    #[test]
    fn bps_ceil_rounding() {
        assert_eq!(percent_from_bps_ceil(0), 0);
        assert_eq!(percent_from_bps_ceil(100), 1);
        assert_eq!(percent_from_bps_ceil(150), 2);
        assert_eq!(percent_from_bps_ceil(9500), 95);
        assert_eq!(percent_from_bps_ceil(10_000), 100);
        assert_eq!(percent_from_bps_ceil(10_001), 100);
    }

    #[test]
    fn rate_bps_zero_samples() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        assert_eq!(success_rate_bps(&r), 10_000);
        assert_eq!(error_rate_bps(&r), 0);
    }

    #[test]
    fn rate_bps_with_data() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        for _ in 0..9 {
            r.update_health(true, Some(10));
        }
        r.update_health(false, Some(500));
        assert_eq!(success_rate_bps(&r), 9000);
        assert_eq!(error_rate_bps(&r), 1000);
    }

    #[test]
    fn health_score_clamp() {
        assert_eq!(health_score_percent(0), 0);
        assert_eq!(health_score_percent(100), 100);
        assert_eq!(health_score_percent(255), 100);
    }

    #[test]
    fn health_fields_variants() {
        let (s, r) = connector_health_fields(&ConnectorHealth::healthy());
        assert_eq!(s, "healthy");
        assert!(r.is_none());
        let (s, r) = connector_health_fields(&ConnectorHealth::Degraded {
            reason: "slow".into(),
        });
        assert_eq!(s, "degraded");
        assert_eq!(r.as_deref(), Some("slow"));
        let (s, r) = connector_health_fields(&ConnectorHealth::Unavailable {
            reason: "down".into(),
            since: Utc::now(),
        });
        assert_eq!(s, "unavailable");
        assert_eq!(r.as_deref(), Some("down"));
    }

    #[test]
    fn health_reason_none_healthy() {
        assert!(connector_health_reason(&ConnectorHealth::healthy()).is_none());
    }

    #[test]
    fn status_labels() {
        assert_eq!(self_check_status_label(&SelfCheckReport::ok()), "ok");
        assert_eq!(
            self_check_status_label(&SelfCheckReport::unsupported()),
            "unsupported"
        );
        assert_eq!(
            self_check_status_label(&SelfCheckReport::failed("c", "m")),
            "failed"
        );
    }

    #[test]
    fn explain_uses_message_then_code_then_label() {
        let r1 = SelfCheckReport::failed("code", "message");
        assert_eq!(explain_self_check(&r1), "message");
        let mut r2 = SelfCheckReport::failed("code", "m");
        r2.message = None;
        assert_eq!(explain_self_check(&r2), "code");
        let mut r3 = SelfCheckReport::failed("c", "m");
        r3.message = None;
        r3.reason_code = None;
        assert!(explain_self_check(&r3).contains("failed"));
    }

    #[test]
    fn lifecycle_error_mapping() {
        assert!(matches!(
            map_lifecycle_error(LifecycleError::NotFound {
                connector_id: connector_id()
            }),
            HostError::ConnectorNotFound(_)
        ));
        assert!(matches!(
            map_lifecycle_error(LifecycleError::NoRollbackTarget),
            HostError::Internal(_)
        ));
    }

    #[test]
    fn canary_reason_variants() {
        assert!(matches!(
            canary_reason(
                Some(&semver::Version::new(1, 0, 0)),
                &semver::Version::new(1, 1, 0)
            ),
            TransitionReason::NewVersion { .. }
        ));
        assert!(matches!(
            canary_reason(None, &semver::Version::new(2, 0, 0)),
            TransitionReason::InstallComplete
        ));
    }

    #[test]
    fn canary_policy_from_rollout() {
        let cp = to_canary_policy(&rollout_policy());
        assert_eq!(cp.canary_traffic_percent, 5);
        assert_eq!(cp.min_canary_duration_secs, 120);
        assert_eq!(cp.min_samples, 5);
    }

    #[test]
    fn evidence_roundtrip() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let j = serde_json::to_string(&e).unwrap();
        let d: RolloutEvidence = serde_json::from_str(&j).unwrap();
        assert_eq!(e.reason_code, d.reason_code);
    }

    #[test]
    fn evidence_digest_differs() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let now = Utc::now();
        let a = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "a",
            message: "a",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: now,
        });
        let b = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "b",
            message: "b",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: now,
        });
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn audit_event_digest_and_roundtrip() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let evt = build_audit_event(
            &connector_id(),
            LifecycleState::Canary,
            LifecycleState::Canary,
            RolloutDecision::Hold,
            &e,
        );
        assert!(evt.evidence_digest.starts_with("blake3-256:"));
        let j = serde_json::to_string(&evt).unwrap();
        let d: RolloutAuditEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(evt.reason_code, d.reason_code);
    }

    fn make_canary_record() -> LifecycleRecord {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.previous_version = Some(semver::Version::new(0, 9, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        r
    }

    #[test]
    fn eval_not_canary_holds() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "state_not_canary");
    }

    #[test]
    fn eval_self_check_failed() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::failed("db", "down"),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "self_check_failed");
    }

    #[test]
    fn eval_unavailable() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Unavailable {
                reason: "x".into(),
                since: Utc::now(),
            },
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "connector_unavailable");
    }

    #[test]
    fn eval_crash_loop() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            true,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "crash_loop_detected");
    }

    #[test]
    fn eval_error_rate() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(false, Some(100));
        }
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(false, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "error_rate_exceeded");
    }

    #[test]
    fn eval_pinned() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .pinned(true),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "pinned");
    }

    #[test]
    fn eval_degraded_self_check() {
        let r = make_canary_record();
        let mut sc = SelfCheckReport::ok();
        sc.status = SelfCheckStatus::Degraded;
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &sc,
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "self_check_degraded");
    }

    #[test]
    fn eval_degraded_connector() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Degraded {
                reason: "mem".into(),
            },
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "connector_degraded");
    }

    #[test]
    fn eval_self_check_required() {
        let r = make_canary_record();
        let cfg = RolloutControllerConfig {
            allow_unsupported_self_check_promotion: false,
            ..RolloutControllerConfig::default()
        };
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::unsupported(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &cfg,
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "self_check_required");
    }

    #[test]
    fn eval_uptime_low() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(5),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "uptime_too_low");
    }

    #[test]
    fn canary_elapsed_non_canary_none() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        assert!(canary_elapsed_secs(&r, Utc::now()).is_none());
    }

    #[test]
    fn canary_elapsed_positive() {
        let r = make_canary_record();
        assert!(canary_elapsed_secs(&r, Utc::now()).is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_from_production() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        lm.promote(&connector_id()).await.unwrap();
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Scheduled);
        assert_eq!(o.record.state, LifecycleState::Canary);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_unknown_connector_errs() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg, lm);
        let unk = ConnectorId::from_static("fcp.unknown:utility:1.0.0");
        assert!(
            ctrl.schedule_canary(
                &unk,
                semver::Version::new(1, 0, 0),
                None,
                &rollout_policy(),
                Utc::now()
            )
            .await
            .is_err()
        );
        assert!(
            ctrl.evaluate(&unk, RolloutObservation::new(true, rollout_policy()))
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_degraded_holds() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::Degraded {
                reason: "lat".into(),
            }),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Hold);
        assert_eq!(o.audit_event.reason_code, "connector_degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_unavailable_rolls_back() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::Unavailable {
                reason: "killed".into(),
                since: Utc::now(),
            }),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Rollback);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_uptime_low_holds() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_uptime_secs(5)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Hold);
        assert_eq!(o.audit_event.reason_code, "uptime_too_low");
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_custom_config() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let cfg = RolloutControllerConfig {
            min_uptime_secs_for_promotion: 300,
            allow_unsupported_self_check_promotion: false,
            crash_loop_threshold: 5,
            crash_loop_window_secs: 600,
        };
        let ctrl = RolloutController::with_config(reg, lm, cfg);
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 0, 0),
                None,
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Scheduled);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_reschedule_resets_health() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        let _ = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_uptime_secs(50)
                    .observed_at(Utc::now()),
            )
            .await;
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.record.health.samples, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_version_tracking() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg, lm);
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(2, 0, 0),
                Some(semver::Version::new(1, 5, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.record.version, semver::Version::new(2, 0, 0));
        assert_eq!(
            o.record.previous_version,
            Some(semver::Version::new(1, 5, 0))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_from_rolled_back() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        lm.rollback(&connector_id(), Some("bad".into()))
            .await
            .unwrap();
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 0, 1),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Scheduled);
        assert_eq!(o.record.state, LifecycleState::Canary);
    }

    #[test]
    fn evidence_fields_reflect_inputs() {
        let mut r = make_canary_record();
        for _ in 0..8 {
            r.update_health(true, Some(25));
        }
        for _ in 0..2 {
            r.update_health(false, Some(500));
        }
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: true,
            crash_loop_detected: true,
            failure_streak: 7,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::Degraded {
                reason: "slow".into(),
            },
            uptime_secs: 42,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert!(e.pinned);
        assert!(e.crash_loop_detected);
        assert_eq!(e.failure_streak, 7);
        assert_eq!(e.uptime_secs, 42);
        assert_eq!(e.connector_health_status, "degraded");
        assert_eq!(e.success_rate_bps, 8000);
        assert_eq!(e.error_rate_bps, 2000);
        assert_eq!(e.samples, 10);
    }
}
