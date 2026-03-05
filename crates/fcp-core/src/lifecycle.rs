//! Connector lifecycle state machine and canary rollout policy (NORMATIVE).
//!
//! This module implements the deployment lifecycle for connectors as described
//! in the FCP Specification. It manages the progression from canary to production
//! with health-based promotion and automatic rollback.
//!
//! # Lifecycle States
//!
//! ```text
//! ┌─────────────┐    health OK    ┌─────────────┐
//! │   Canary    │ ───────────────►│ Production  │
//! └─────────────┘                 └─────────────┘
//!        │                               │
//!        │ health fail                   │ new version
//!        ▼                               ▼
//! ┌─────────────┐                 ┌─────────────┐
//! │ RolledBack  │◄────────────────│   Canary    │
//! └─────────────┘    rollback     └─────────────┘
//! ```
//!
//! # Key Invariants
//!
//! - State transitions are atomic and logged to the audit chain
//! - Lifecycle state persists across host restarts
//! - Health failures during canary trigger automatic rollback
//! - Manual promotion/rollback is always available

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;

use crate::ConnectorId;

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle State
// ─────────────────────────────────────────────────────────────────────────────

/// Connector deployment lifecycle state (NORMATIVE).
///
/// Defines the current deployment phase of a connector version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Initial state before any deployment.
    #[default]
    Pending,

    /// Connector is being installed/verified.
    Installing,

    /// Connector is in canary rollout (limited traffic).
    Canary,

    /// Connector is in full production.
    Production,

    /// Connector was rolled back due to health failure.
    RolledBack,

    /// Connector has been explicitly disabled.
    Disabled,

    /// Connector has been uninstalled.
    Uninstalled,
}

impl LifecycleState {
    /// Check if this state allows receiving traffic.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Canary | Self::Production)
    }

    /// Check if this state can transition to canary.
    #[must_use]
    pub const fn can_start_canary(&self) -> bool {
        matches!(
            self,
            Self::Installing | Self::Production | Self::RolledBack | Self::Disabled
        )
    }

    /// Check if this state can be promoted to production.
    #[must_use]
    pub const fn can_promote(&self) -> bool {
        matches!(self, Self::Canary)
    }

    /// Check if this state can be rolled back.
    #[must_use]
    pub const fn can_rollback(&self) -> bool {
        matches!(self, Self::Canary | Self::Production)
    }

    /// Get the string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Installing => "installing",
            Self::Canary => "canary",
            Self::Production => "production",
            Self::RolledBack => "rolled_back",
            Self::Disabled => "disabled",
            Self::Uninstalled => "uninstalled",
        }
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle Transition
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state transition event (NORMATIVE).
///
/// Records a state change for audit purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTransition {
    /// Previous state.
    pub from: LifecycleState,

    /// New state.
    pub to: LifecycleState,

    /// Reason for the transition.
    pub reason: TransitionReason,

    /// Timestamp of the transition.
    pub timestamp: DateTime<Utc>,

    /// Optional operator who initiated the transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
}

impl LifecycleTransition {
    /// Create a new transition.
    #[must_use]
    pub fn new(from: LifecycleState, to: LifecycleState, reason: TransitionReason) -> Self {
        Self {
            from,
            to,
            reason,
            timestamp: Utc::now(),
            initiated_by: None,
        }
    }

    /// Set the initiator.
    #[must_use]
    pub fn with_initiator(mut self, initiator: impl Into<String>) -> Self {
        self.initiated_by = Some(initiator.into());
        self
    }
}

/// Reason for a lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransitionReason {
    /// Installation completed successfully.
    InstallComplete,

    /// Manual promotion by operator.
    ManualPromotion,

    /// Automatic promotion based on health metrics.
    AutoPromotion {
        /// Health score that triggered promotion.
        health_score: u8,
    },

    /// Manual rollback by operator.
    ManualRollback {
        /// Optional reason provided by operator.
        reason: Option<String>,
    },

    /// Automatic rollback due to health failure.
    AutoRollback {
        /// Health score that triggered rollback.
        health_score: u8,
        /// Specific failure reason.
        failure_reason: String,
    },

    /// Connector was disabled.
    Disabled {
        /// Reason for disabling.
        reason: String,
    },

    /// Connector was uninstalled.
    Uninstalled,

    /// New version deployed (resets to canary).
    NewVersion {
        /// Previous version.
        from_version: String,
        /// New version.
        to_version: String,
    },
}

impl fmt::Display for TransitionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstallComplete => write!(f, "installation completed"),
            Self::ManualPromotion => write!(f, "manual promotion"),
            Self::AutoPromotion { health_score } => {
                write!(f, "auto-promotion (health: {health_score}%)")
            }
            Self::ManualRollback { reason } => {
                if let Some(r) = reason {
                    write!(f, "manual rollback: {r}")
                } else {
                    write!(f, "manual rollback")
                }
            }
            Self::AutoRollback {
                health_score,
                failure_reason,
            } => {
                write!(
                    f,
                    "auto-rollback (health: {health_score}%, reason: {failure_reason})"
                )
            }
            Self::Disabled { reason } => write!(f, "disabled: {reason}"),
            Self::Uninstalled => write!(f, "uninstalled"),
            Self::NewVersion {
                from_version,
                to_version,
            } => write!(f, "new version: {from_version} -> {to_version}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle Record
// ─────────────────────────────────────────────────────────────────────────────

/// Persistent lifecycle record for a connector deployment (NORMATIVE).
///
/// This record is persisted to the mesh and survives host restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRecord {
    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Deployed version.
    pub version: semver::Version,

    /// Current lifecycle state.
    pub state: LifecycleState,

    /// When this deployment started.
    pub deployed_at: DateTime<Utc>,

    /// When the state last changed.
    pub state_changed_at: DateTime<Utc>,

    /// History of state transitions.
    #[serde(default)]
    pub transitions: Vec<LifecycleTransition>,

    /// Current health metrics.
    pub health: HealthMetrics,

    /// Canary policy for this deployment.
    pub canary_policy: CanaryPolicy,

    /// Previous version (for rollback).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<semver::Version>,
}

impl LifecycleRecord {
    /// Create a new lifecycle record for a pending deployment.
    #[must_use]
    pub fn new(connector_id: ConnectorId, version: semver::Version) -> Self {
        let now = Utc::now();
        Self {
            connector_id,
            version,
            state: LifecycleState::Pending,
            deployed_at: now,
            state_changed_at: now,
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        }
    }

    /// Set the canary policy.
    #[must_use]
    pub const fn with_canary_policy(mut self, policy: CanaryPolicy) -> Self {
        self.canary_policy = policy;
        self
    }

    /// Set the previous version (for rollback target).
    #[must_use]
    pub fn with_previous_version(mut self, version: semver::Version) -> Self {
        self.previous_version = Some(version);
        self
    }

    /// Transition to a new state.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::InvalidTransition`] if the transition is not allowed.
    pub fn transition(
        &mut self,
        to: LifecycleState,
        reason: TransitionReason,
    ) -> Result<(), LifecycleError> {
        self.validate_transition(to)?;

        let transition = LifecycleTransition::new(self.state, to, reason);
        self.transitions.push(transition);
        self.state = to;
        self.state_changed_at = Utc::now();

        Ok(())
    }

    /// Validate that a transition is allowed.
    const fn validate_transition(&self, to: LifecycleState) -> Result<(), LifecycleError> {
        // Valid transitions are defined by the state machine diagram.
        // Using nested or-patterns for clippy::unnested_or_patterns.
        let valid = matches!(
            (self.state, to),
            // Pending -> Installing or Uninstalled
            (LifecycleState::Pending, LifecycleState::Installing | LifecycleState::Uninstalled)
                // Installing/Production/RolledBack/Disabled -> Canary
                | (
                    LifecycleState::Installing
                        | LifecycleState::Production
                        | LifecycleState::RolledBack
                        | LifecycleState::Disabled,
                    LifecycleState::Canary
                )
                // Most states -> Uninstalled
                | (
                    LifecycleState::Installing
                        | LifecycleState::Canary
                        | LifecycleState::Production
                        | LifecycleState::RolledBack
                        | LifecycleState::Disabled,
                    LifecycleState::Uninstalled
                )
                // Canary -> Production/RolledBack/Disabled
                | (
                    LifecycleState::Canary,
                    LifecycleState::Production | LifecycleState::RolledBack | LifecycleState::Disabled
                )
                // Production -> RolledBack/Disabled
                | (
                    LifecycleState::Production,
                    LifecycleState::RolledBack | LifecycleState::Disabled
                )
                // RolledBack -> Disabled
                | (LifecycleState::RolledBack, LifecycleState::Disabled)
        );

        if valid {
            Ok(())
        } else {
            Err(LifecycleError::InvalidTransition {
                from: self.state,
                to,
            })
        }
    }

    /// Check if the connector should be auto-promoted based on health.
    #[must_use]
    pub fn should_auto_promote(&self) -> bool {
        self.should_auto_promote_at(Utc::now())
    }

    /// Check if the connector should be auto-rolled-back based on health.
    #[must_use]
    pub fn should_auto_rollback(&self) -> bool {
        self.state == LifecycleState::Canary
            && self.health.success_rate < self.canary_policy.rollback_threshold
            && self.health.samples >= self.canary_policy.min_samples
    }

    /// Check if the connector should be auto-promoted at a specific instant.
    #[must_use]
    pub fn should_auto_promote_at(&self, now: DateTime<Utc>) -> bool {
        self.state == LifecycleState::Canary
            && self.health.success_rate >= self.canary_policy.promotion_threshold
            && self.health.samples >= self.canary_policy.min_samples
            && self.canary_duration_exceeded_at(now)
    }

    /// Compute remaining canary time at a specific instant, if currently in canary.
    #[must_use]
    pub fn canary_expires_in_secs_at(&self, now: DateTime<Utc>) -> Option<u32> {
        if self.state != LifecycleState::Canary {
            return None;
        }

        let elapsed = now
            .signed_duration_since(self.canary_start_timestamp())
            .num_seconds();
        let max = i64::from(self.canary_policy.max_canary_duration_secs);
        if elapsed <= 0 {
            return Some(self.canary_policy.max_canary_duration_secs);
        }
        if elapsed >= max {
            return Some(0);
        }

        u32::try_from(max - elapsed).ok()
    }

    fn canary_duration_exceeded_at(&self, now: DateTime<Utc>) -> bool {
        let duration = now.signed_duration_since(self.canary_start_timestamp());
        duration.num_seconds() >= i64::from(self.canary_policy.min_canary_duration_secs)
    }

    fn canary_start_timestamp(&self) -> DateTime<Utc> {
        self.transitions
            .iter()
            .rev()
            .find(|t| t.to == LifecycleState::Canary)
            .map_or(self.deployed_at, |t| t.timestamp)
    }

    /// Update health metrics.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn update_health(&mut self, success: bool, latency_ms: Option<u32>) {
        self.health.samples += 1;
        if success {
            self.health.successes += 1;
        } else {
            self.health.failures += 1;
        }

        // Update success rate (clamped to 0-100)
        if self.health.samples > 0 {
            let rate = (self.health.successes as f64 / self.health.samples as f64 * 100.0).min(100.0);
            self.health.success_rate = rate as u8;
        }

        // Update latency tracking
        if let Some(latency) = latency_ms {
            self.health.total_latency_ms += u64::from(latency);
            self.health.latency_samples += 1;
            if latency > self.health.max_latency_ms {
                self.health.max_latency_ms = latency;
            }
        }

        self.health.last_updated = Utc::now();
    }

    /// Reset health metrics (e.g., when entering canary).
    pub fn reset_health(&mut self) {
        self.health = HealthMetrics::default();
    }

    /// Record a crash and rollback when a crash loop is detected.
    ///
    /// Returns `Ok(true)` when the crash threshold is reached and rollback is applied.
    /// Returns `Ok(false)` when the threshold is not yet reached.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`LifecycleError::NoRollbackTarget`] if crash-loop threshold is reached but no previous
    ///   version is available.
    /// - [`LifecycleError::InvalidTransition`] if crash-loop threshold is reached but current
    ///   state cannot transition to `RolledBack`.
    pub fn record_crash_and_maybe_rollback(
        &mut self,
        detector: &mut CrashLoopDetector,
        at: DateTime<Utc>,
        failure_reason: impl Into<String>,
    ) -> Result<bool, LifecycleError> {
        detector.record_crash(at);
        if !detector.is_crash_loop(at) {
            return Ok(false);
        }

        if self.previous_version.is_none() {
            return Err(LifecycleError::NoRollbackTarget);
        }

        self.transition(
            LifecycleState::RolledBack,
            TransitionReason::AutoRollback {
                health_score: self.health.success_rate,
                failure_reason: failure_reason.into(),
            },
        )?;

        // Start clean after rollback so a retried canary doesn't inherit prior crash history.
        detector.record_success();
        Ok(true)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Metrics
// ─────────────────────────────────────────────────────────────────────────────

/// Health metrics for a connector deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Number of successful invocations.
    pub successes: u64,

    /// Number of failed invocations.
    pub failures: u64,

    /// Total number of samples.
    pub samples: u64,

    /// Success rate as a percentage (0-100).
    pub success_rate: u8,

    /// Total latency in milliseconds (for average calculation).
    pub total_latency_ms: u64,

    /// Number of samples that included latency data (for correct average).
    pub latency_samples: u64,

    /// Maximum observed latency.
    pub max_latency_ms: u32,

    /// When metrics were last updated.
    pub last_updated: DateTime<Utc>,
}

impl Default for HealthMetrics {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            samples: 0,
            success_rate: 100, // Start optimistic
            total_latency_ms: 0,
            latency_samples: 0,
            max_latency_ms: 0,
            last_updated: Utc::now(),
        }
    }
}

impl HealthMetrics {
    /// Calculate average latency in milliseconds.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn avg_latency_ms(&self) -> Option<u32> {
        self.total_latency_ms
            .checked_div(self.latency_samples)
            .map(|avg| u32::try_from(avg).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crash Loop Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Sliding-window crash-loop detector for connector supervisors.
///
/// A connector is considered to be crash-looping when at least `max_crashes`
/// crashes occur within `window_secs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashLoopDetector {
    /// Number of crashes that triggers crash-loop classification.
    pub max_crashes: usize,

    /// Sliding window in seconds for crash counting.
    pub window_secs: i64,

    /// Ordered crash timestamps (oldest first).
    #[serde(default)]
    crashes: VecDeque<DateTime<Utc>>,
}

impl CrashLoopDetector {
    /// Create a crash-loop detector with explicit threshold and window.
    #[must_use]
    pub const fn new(max_crashes: usize, window_secs: i64) -> Self {
        Self {
            max_crashes,
            window_secs,
            crashes: VecDeque::new(),
        }
    }

    /// Record a crash at the provided timestamp.
    pub fn record_crash(&mut self, at: DateTime<Utc>) {
        self.prune_old(at);
        self.crashes.push_back(at);
    }

    /// Record a successful run and reset crash history.
    pub fn record_success(&mut self) {
        self.crashes.clear();
    }

    /// Return how many crashes are currently inside the active window.
    pub fn crash_count_in_window(&mut self, now: DateTime<Utc>) -> usize {
        self.prune_old(now);
        self.crashes.len()
    }

    /// Return true when crash-loop threshold is met in the active window.
    pub fn is_crash_loop(&mut self, now: DateTime<Utc>) -> bool {
        self.crash_count_in_window(now) >= self.max_crashes
    }

    fn prune_old(&mut self, now: DateTime<Utc>) {
        if self.window_secs < 0 {
            self.crashes.clear();
            return;
        }

        let cutoff = now - chrono::Duration::seconds(self.window_secs);
        while self.crashes.front().is_some_and(|ts| *ts < cutoff) {
            let _ = self.crashes.pop_front();
        }
    }
}

impl Default for CrashLoopDetector {
    fn default() -> Self {
        Self::new(5, 300)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canary Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy for canary rollout behavior (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryPolicy {
    /// Minimum success rate (%) to auto-promote to production.
    pub promotion_threshold: u8,

    /// Success rate (%) below which to auto-rollback.
    pub rollback_threshold: u8,

    /// Minimum samples before making promotion/rollback decisions.
    pub min_samples: u64,

    /// Minimum time in canary before allowing promotion (seconds).
    pub min_canary_duration_secs: u32,

    /// Maximum time in canary before requiring decision (seconds).
    pub max_canary_duration_secs: u32,

    /// Percentage of traffic to route to canary (0-100).
    pub canary_traffic_percent: u8,
}

impl Default for CanaryPolicy {
    fn default() -> Self {
        Self {
            promotion_threshold: 95,        // 95% success rate to promote
            rollback_threshold: 80,         // 80% success rate triggers rollback
            min_samples: 100,               // At least 100 invocations
            min_canary_duration_secs: 300,  // 5 minutes minimum
            max_canary_duration_secs: 3600, // 1 hour maximum
            canary_traffic_percent: 10,     // 10% of traffic
        }
    }
}

impl CanaryPolicy {
    /// Create a new canary policy with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the promotion threshold.
    #[must_use]
    pub const fn with_promotion_threshold(mut self, threshold: u8) -> Self {
        self.promotion_threshold = threshold;
        self
    }

    /// Set the rollback threshold.
    #[must_use]
    pub const fn with_rollback_threshold(mut self, threshold: u8) -> Self {
        self.rollback_threshold = threshold;
        self
    }

    /// Set the minimum samples.
    #[must_use]
    pub const fn with_min_samples(mut self, samples: u64) -> Self {
        self.min_samples = samples;
        self
    }

    /// Set the minimum canary duration.
    #[must_use]
    pub const fn with_min_canary_duration(mut self, secs: u32) -> Self {
        self.min_canary_duration_secs = secs;
        self
    }

    /// Set the canary traffic percentage.
    #[must_use]
    pub const fn with_canary_traffic_percent(mut self, percent: u8) -> Self {
        self.canary_traffic_percent = percent;
        self
    }

    /// Validate the policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::InvalidPolicy`] if:
    /// - `promotion_threshold` is not greater than `rollback_threshold`
    /// - `canary_traffic_percent` is greater than 100
    /// - `max_canary_duration_secs` is less than `min_canary_duration_secs`
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.promotion_threshold <= self.rollback_threshold {
            return Err(LifecycleError::InvalidPolicy {
                reason: "promotion_threshold must be greater than rollback_threshold".to_string(),
            });
        }
        if self.canary_traffic_percent > 100 {
            return Err(LifecycleError::InvalidPolicy {
                reason: "canary_traffic_percent must be 0-100".to_string(),
            });
        }
        if self.max_canary_duration_secs < self.min_canary_duration_secs {
            return Err(LifecycleError::InvalidPolicy {
                reason: "max_canary_duration must be >= min_canary_duration".to_string(),
            });
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// Invalid state transition.
    InvalidTransition {
        /// Current state.
        from: LifecycleState,
        /// Attempted target state.
        to: LifecycleState,
    },

    /// Invalid policy configuration.
    InvalidPolicy {
        /// Reason for invalidity.
        reason: String,
    },

    /// Connector not found.
    NotFound {
        /// Connector ID.
        connector_id: ConnectorId,
    },

    /// Rollback target not available.
    NoRollbackTarget,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition from {from} to {to}")
            }
            Self::InvalidPolicy { reason } => {
                write!(f, "invalid canary policy: {reason}")
            }
            Self::NotFound { connector_id } => {
                write!(f, "connector not found: {connector_id}")
            }
            Self::NoRollbackTarget => {
                write!(f, "no previous version available for rollback")
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle Manager Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for managing connector lifecycle (NORMATIVE).
///
/// Implementations persist lifecycle state and coordinate with the mesh.
#[async_trait::async_trait]
pub trait LifecycleManager: Send + Sync {
    /// Get the current lifecycle record for a connector.
    async fn get(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, LifecycleError>;

    /// Save a lifecycle record.
    async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError>;

    /// Promote a connector from canary to production.
    async fn promote(&self, connector_id: &ConnectorId) -> Result<LifecycleRecord, LifecycleError>;

    /// Rollback a connector to the previous version.
    async fn rollback(
        &self,
        connector_id: &ConnectorId,
        reason: Option<String>,
    ) -> Result<LifecycleRecord, LifecycleError>;

    /// Get the status of a connector.
    async fn status(&self, connector_id: &ConnectorId) -> Result<LifecycleStatus, LifecycleError>;
}

/// Summary status for a connector lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleStatus {
    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Current state.
    pub state: LifecycleState,

    /// Current version.
    pub version: semver::Version,

    /// Health metrics summary.
    pub health: HealthMetrics,

    /// Whether auto-promotion is pending.
    pub auto_promote_pending: bool,

    /// Whether auto-rollback is pending.
    pub auto_rollback_pending: bool,

    /// Time until canary expires (if in canary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary_expires_in_secs: Option<u32>,

    /// Whether a crash-loop condition is currently detected.
    #[serde(default)]
    pub crash_loop_detected: bool,

    /// Previous version available for rollback, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_target_version: Option<semver::Version>,
}

impl LifecycleStatus {
    /// Build status from a lifecycle record with explicit crash-loop signal.
    #[must_use]
    pub fn from_record(
        record: &LifecycleRecord,
        now: DateTime<Utc>,
        crash_loop_detected: bool,
    ) -> Self {
        Self {
            connector_id: record.connector_id.clone(),
            state: record.state,
            version: record.version.clone(),
            health: record.health.clone(),
            auto_promote_pending: record.should_auto_promote_at(now),
            auto_rollback_pending: record.should_auto_rollback() || crash_loop_detected,
            canary_expires_in_secs: record.canary_expires_in_secs_at(now),
            crash_loop_detected,
            rollback_target_version: record.previous_version.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("test:lifecycle:v1")
    }

    fn test_version() -> semver::Version {
        semver::Version::new(1, 0, 0)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_state_is_active() {
        assert!(!LifecycleState::Pending.is_active());
        assert!(!LifecycleState::Installing.is_active());
        assert!(LifecycleState::Canary.is_active());
        assert!(LifecycleState::Production.is_active());
        assert!(!LifecycleState::RolledBack.is_active());
        assert!(!LifecycleState::Disabled.is_active());
        assert!(!LifecycleState::Uninstalled.is_active());
    }

    #[test]
    fn lifecycle_state_can_promote() {
        assert!(!LifecycleState::Pending.can_promote());
        assert!(!LifecycleState::Installing.can_promote());
        assert!(LifecycleState::Canary.can_promote());
        assert!(!LifecycleState::Production.can_promote());
        assert!(!LifecycleState::RolledBack.can_promote());
    }

    #[test]
    fn lifecycle_state_can_rollback() {
        assert!(!LifecycleState::Pending.can_rollback());
        assert!(LifecycleState::Canary.can_rollback());
        assert!(LifecycleState::Production.can_rollback());
        assert!(!LifecycleState::RolledBack.can_rollback());
    }

    #[test]
    fn lifecycle_state_display() {
        assert_eq!(LifecycleState::Canary.to_string(), "canary");
        assert_eq!(LifecycleState::Production.to_string(), "production");
        assert_eq!(LifecycleState::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn lifecycle_state_serde_roundtrip() {
        for state in [
            LifecycleState::Pending,
            LifecycleState::Installing,
            LifecycleState::Canary,
            LifecycleState::Production,
            LifecycleState::RolledBack,
            LifecycleState::Disabled,
            LifecycleState::Uninstalled,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let decoded: LifecycleState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, decoded);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleRecord Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_record_new() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        assert_eq!(record.state, LifecycleState::Pending);
        assert!(record.transitions.is_empty());
    }

    #[test]
    fn lifecycle_record_valid_transitions() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());

        // Pending -> Installing
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::Installing);

        // Installing -> Canary
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        assert_eq!(record.state, LifecycleState::Canary);

        // Canary -> Production
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::AutoPromotion { health_score: 98 },
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::Production);

        assert_eq!(record.transitions.len(), 3);
    }

    #[test]
    fn lifecycle_record_invalid_transition() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());

        // Pending -> Production is not allowed
        let result = record.transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        );
        assert!(matches!(
            result,
            Err(LifecycleError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn lifecycle_record_self_transition_not_allowed() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());

        // Pending -> Pending is not allowed
        let result = record.transition(LifecycleState::Pending, TransitionReason::InstallComplete);
        assert!(matches!(
            result,
            Err(LifecycleError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn lifecycle_record_rollback_from_canary() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        // Canary -> RolledBack
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::AutoRollback {
                    health_score: 75,
                    failure_reason: "high error rate".to_string(),
                },
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::RolledBack);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Health Metrics Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_metrics_update() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());

        // Add successes
        for _ in 0..9 {
            record.update_health(true, Some(100));
        }
        // Add one failure
        record.update_health(false, Some(500));

        assert_eq!(record.health.samples, 10);
        assert_eq!(record.health.successes, 9);
        assert_eq!(record.health.failures, 1);
        assert_eq!(record.health.success_rate, 90);
        assert_eq!(record.health.max_latency_ms, 500);
    }

    #[test]
    fn health_metrics_avg_latency() {
        let metrics = HealthMetrics {
            samples: 4,
            latency_samples: 4,
            total_latency_ms: 400,
            ..Default::default()
        };

        assert_eq!(metrics.avg_latency_ms(), Some(100));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CanaryPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_policy_default() {
        let policy = CanaryPolicy::default();
        assert_eq!(policy.promotion_threshold, 95);
        assert_eq!(policy.rollback_threshold, 80);
        assert_eq!(policy.min_samples, 100);
    }

    #[test]
    fn canary_policy_builder() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(99)
            .with_rollback_threshold(90)
            .with_min_samples(50)
            .with_canary_traffic_percent(5);

        assert_eq!(policy.promotion_threshold, 99);
        assert_eq!(policy.rollback_threshold, 90);
        assert_eq!(policy.min_samples, 50);
        assert_eq!(policy.canary_traffic_percent, 5);
    }

    #[test]
    fn canary_policy_validate_valid() {
        let policy = CanaryPolicy::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_validate_invalid_thresholds() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(80)
            .with_rollback_threshold(90); // Higher than promotion!

        assert!(matches!(
            policy.validate(),
            Err(LifecycleError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn canary_policy_validate_invalid_traffic() {
        let policy = CanaryPolicy::new().with_canary_traffic_percent(150);

        assert!(matches!(
            policy.validate(),
            Err(LifecycleError::InvalidPolicy { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Auto Promotion/Rollback Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn should_auto_promote_when_healthy() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_promotion_threshold(90)
                    .with_min_samples(10)
                    .with_min_canary_duration(0), // No minimum for test
            );

        // Transition to canary
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        // Add healthy samples
        for _ in 0..10 {
            record.update_health(true, Some(100));
        }

        assert!(record.should_auto_promote());
    }

    #[test]
    fn should_auto_rollback_when_unhealthy() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(10),
            );

        // Transition to canary
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        // Add unhealthy samples (70% success)
        for _ in 0..7 {
            record.update_health(true, Some(100));
        }
        for _ in 0..3 {
            record.update_health(false, Some(100));
        }

        assert!(record.should_auto_rollback());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TransitionReason Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transition_reason_display() {
        assert_eq!(
            TransitionReason::ManualPromotion.to_string(),
            "manual promotion"
        );
        assert_eq!(
            TransitionReason::AutoPromotion { health_score: 98 }.to_string(),
            "auto-promotion (health: 98%)"
        );
        assert_eq!(
            TransitionReason::AutoRollback {
                health_score: 75,
                failure_reason: "timeout".to_string()
            }
            .to_string(),
            "auto-rollback (health: 75%, reason: timeout)"
        );
    }

    // ── Additional coverage ──

    #[test]
    fn lifecycle_state_default_is_pending() {
        assert_eq!(LifecycleState::default(), LifecycleState::Pending);
    }

    #[test]
    fn lifecycle_state_can_start_canary() {
        // Pending cannot go directly to Canary (must go through Installing first)
        assert!(!LifecycleState::Pending.can_start_canary());
        // These match the valid transitions in validate_transition:
        // Installing/Production/RolledBack/Disabled -> Canary
        assert!(LifecycleState::Installing.can_start_canary());
        assert!(LifecycleState::Production.can_start_canary());
        assert!(LifecycleState::RolledBack.can_start_canary());
        assert!(LifecycleState::Disabled.can_start_canary());
        // Canary/Uninstalled cannot transition to Canary
        assert!(!LifecycleState::Canary.can_start_canary());
        assert!(!LifecycleState::Uninstalled.can_start_canary());
    }

    #[test]
    fn lifecycle_state_as_str_all_variants() {
        assert_eq!(LifecycleState::Pending.as_str(), "pending");
        assert_eq!(LifecycleState::Installing.as_str(), "installing");
        assert_eq!(LifecycleState::Canary.as_str(), "canary");
        assert_eq!(LifecycleState::Production.as_str(), "production");
        assert_eq!(LifecycleState::RolledBack.as_str(), "rolled_back");
        assert_eq!(LifecycleState::Disabled.as_str(), "disabled");
        assert_eq!(LifecycleState::Uninstalled.as_str(), "uninstalled");
    }

    #[test]
    fn lifecycle_error_display() {
        let err = LifecycleError::InvalidTransition {
            from: LifecycleState::Pending,
            to: LifecycleState::Production,
        };
        let msg = err.to_string();
        assert!(msg.contains("pending"));
        assert!(msg.contains("production"));

        let err = LifecycleError::InvalidPolicy {
            reason: "bad threshold".into(),
        };
        assert!(err.to_string().contains("bad threshold"));

        let err = LifecycleError::NotFound {
            connector_id: test_connector_id(),
        };
        assert!(err.to_string().contains("not found"));

        let err = LifecycleError::NoRollbackTarget;
        assert!(err.to_string().contains("rollback"));
    }

    #[test]
    fn lifecycle_transition_with_initiator() {
        let t = LifecycleTransition::new(
            LifecycleState::Canary,
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .with_initiator("operator@example.com");
        assert_eq!(t.initiated_by.as_deref(), Some("operator@example.com"));
    }

    #[test]
    fn lifecycle_record_with_previous_version() {
        let record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        assert_eq!(record.previous_version, Some(semver::Version::new(0, 9, 0)));
    }

    #[test]
    fn lifecycle_record_reset_health() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(100));
        record.update_health(false, Some(200));
        assert_eq!(record.health.samples, 2);

        record.reset_health();
        assert_eq!(record.health.samples, 0);
        assert_eq!(record.health.successes, 0);
        assert_eq!(record.health.failures, 0);
    }

    #[test]
    fn health_metrics_default_values() {
        let metrics = HealthMetrics::default();
        assert_eq!(metrics.successes, 0);
        assert_eq!(metrics.failures, 0);
        assert_eq!(metrics.samples, 0);
        assert_eq!(metrics.success_rate, 100); // Optimistic default
        assert_eq!(metrics.total_latency_ms, 0);
        assert_eq!(metrics.max_latency_ms, 0);
    }

    #[test]
    fn health_metrics_avg_latency_zero_samples() {
        let metrics = HealthMetrics::default();
        assert!(metrics.avg_latency_ms().is_none());
    }

    #[test]
    fn crash_loop_detector_triggers_at_exact_threshold() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut detector = CrashLoopDetector::new(3, 60);

        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base - chrono::Duration::seconds(20));
        detector.record_crash(base - chrono::Duration::seconds(10));

        assert!(
            detector.is_crash_loop(base),
            "exact threshold should trigger crash-loop detection"
        );
    }

    #[test]
    fn crash_loop_detector_below_threshold_does_not_trigger() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut detector = CrashLoopDetector::new(3, 60);

        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base - chrono::Duration::seconds(20));

        assert!(
            !detector.is_crash_loop(base),
            "n-1 crashes should not trigger crash-loop detection"
        );
    }

    #[test]
    fn crash_loop_detector_sliding_window_ages_out_old_crashes() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut detector = CrashLoopDetector::new(3, 60);

        detector.record_crash(base - chrono::Duration::seconds(120)); // aged out
        detector.record_crash(base - chrono::Duration::seconds(59)); // in-window
        detector.record_crash(base - chrono::Duration::seconds(10)); // in-window
        assert_eq!(detector.crash_count_in_window(base), 2);
        assert!(!detector.is_crash_loop(base));

        detector.record_crash(base);
        assert_eq!(detector.crash_count_in_window(base), 3);
        assert!(detector.is_crash_loop(base));
    }

    #[test]
    fn crash_loop_detector_resets_after_success() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut detector = CrashLoopDetector::new(3, 60);

        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base - chrono::Duration::seconds(20));
        detector.record_crash(base - chrono::Duration::seconds(10));
        assert!(detector.is_crash_loop(base));

        detector.record_success();
        assert_eq!(detector.crash_count_in_window(base), 0);
        assert!(!detector.is_crash_loop(base));
    }

    #[test]
    fn record_crash_and_maybe_rollback_below_threshold_noop() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        let mut detector = CrashLoopDetector::new(3, 60);
        let rolled_back = record
            .record_crash_and_maybe_rollback(&mut detector, base, "first crash")
            .unwrap();
        assert!(!rolled_back);
        assert_eq!(record.state, LifecycleState::Canary);
    }

    #[test]
    fn record_crash_and_maybe_rollback_triggers_at_threshold() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record.update_health(true, Some(100));
        record.update_health(false, Some(500));

        let mut detector = CrashLoopDetector::new(3, 60);
        assert!(
            !record
                .record_crash_and_maybe_rollback(&mut detector, base, "crash 1")
                .unwrap()
        );
        assert!(
            !record
                .record_crash_and_maybe_rollback(
                    &mut detector,
                    base + chrono::Duration::seconds(10),
                    "crash 2",
                )
                .unwrap()
        );

        let rolled_back = record
            .record_crash_and_maybe_rollback(
                &mut detector,
                base + chrono::Duration::seconds(20),
                "crash loop threshold reached",
            )
            .unwrap();
        assert!(rolled_back);
        assert_eq!(record.state, LifecycleState::RolledBack);
        assert_eq!(detector.crash_count_in_window(base), 0);

        let last_transition = record.transitions.last().unwrap();
        assert_eq!(last_transition.to, LifecycleState::RolledBack);
        assert_eq!(
            last_transition.reason,
            TransitionReason::AutoRollback {
                health_score: 50,
                failure_reason: "crash loop threshold reached".to_string(),
            }
        );
    }

    #[test]
    fn record_crash_and_maybe_rollback_without_target_fails_closed() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        let mut detector = CrashLoopDetector::new(3, 60);
        record
            .record_crash_and_maybe_rollback(&mut detector, base, "crash 1")
            .unwrap();
        record
            .record_crash_and_maybe_rollback(
                &mut detector,
                base + chrono::Duration::seconds(10),
                "crash 2",
            )
            .unwrap();

        let err = record
            .record_crash_and_maybe_rollback(
                &mut detector,
                base + chrono::Duration::seconds(20),
                "crash loop",
            )
            .unwrap_err();
        assert_eq!(err, LifecycleError::NoRollbackTarget);
        assert_eq!(record.state, LifecycleState::Canary);
    }

    #[test]
    fn record_crash_and_maybe_rollback_rejects_non_rollback_state() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        let mut detector = CrashLoopDetector::new(3, 60);

        record
            .record_crash_and_maybe_rollback(&mut detector, base, "crash 1")
            .unwrap();
        record
            .record_crash_and_maybe_rollback(
                &mut detector,
                base + chrono::Duration::seconds(10),
                "crash 2",
            )
            .unwrap();

        let err = record
            .record_crash_and_maybe_rollback(
                &mut detector,
                base + chrono::Duration::seconds(20),
                "crash loop",
            )
            .unwrap_err();

        assert_eq!(
            err,
            LifecycleError::InvalidTransition {
                from: LifecycleState::Pending,
                to: LifecycleState::RolledBack,
            }
        );
        assert_eq!(record.state, LifecycleState::Pending);
    }

    #[test]
    fn canary_policy_validate_invalid_duration() {
        let policy = CanaryPolicy {
            min_canary_duration_secs: 3600,
            max_canary_duration_secs: 300, // Less than min!
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(LifecycleError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn canary_policy_serde_roundtrip() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(99)
            .with_rollback_threshold(70)
            .with_min_samples(50)
            .with_min_canary_duration(120)
            .with_canary_traffic_percent(5);
        let json = serde_json::to_string(&policy).unwrap();
        let back: CanaryPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.promotion_threshold, 99);
        assert_eq!(back.rollback_threshold, 70);
        assert_eq!(back.min_samples, 50);
        assert_eq!(back.min_canary_duration_secs, 120);
        assert_eq!(back.canary_traffic_percent, 5);
    }

    #[test]
    fn transition_production_to_rolled_back() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::ManualRollback {
                    reason: Some("regression found".into()),
                },
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::RolledBack);
    }

    #[test]
    fn transition_to_disabled() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "maintenance".into(),
                },
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::Disabled);
    }

    #[test]
    fn transition_to_uninstalled() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
            .unwrap();
        assert_eq!(record.state, LifecycleState::Uninstalled);
    }

    #[test]
    fn transition_reason_display_all_variants() {
        assert_eq!(
            TransitionReason::InstallComplete.to_string(),
            "installation completed"
        );
        assert_eq!(
            TransitionReason::ManualRollback { reason: None }.to_string(),
            "manual rollback"
        );
        assert_eq!(
            TransitionReason::ManualRollback {
                reason: Some("oops".into())
            }
            .to_string(),
            "manual rollback: oops"
        );
        assert_eq!(
            TransitionReason::Disabled {
                reason: "maintenance".into()
            }
            .to_string(),
            "disabled: maintenance"
        );
        assert_eq!(TransitionReason::Uninstalled.to_string(), "uninstalled");
        assert_eq!(
            TransitionReason::NewVersion {
                from_version: "1.0.0".into(),
                to_version: "2.0.0".into()
            }
            .to_string(),
            "new version: 1.0.0 -> 2.0.0"
        );
    }

    #[test]
    fn update_health_no_latency() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, None);
        assert_eq!(record.health.samples, 1);
        assert_eq!(record.health.successes, 1);
        assert_eq!(record.health.total_latency_ms, 0);
        assert_eq!(record.health.max_latency_ms, 0);
    }

    #[test]
    fn should_not_auto_promote_when_not_canary() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_promotion_threshold(90)
                    .with_min_samples(1)
                    .with_min_canary_duration(0),
            );

        record.update_health(true, Some(100));
        // Still in Pending state
        assert!(!record.should_auto_promote());
    }

    #[test]
    fn should_not_auto_rollback_when_not_canary() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(1),
            );

        record.update_health(false, Some(100));
        // Still in Pending state
        assert!(!record.should_auto_rollback());
    }

    #[test]
    fn canary_expires_in_secs_at_computes_remaining_time() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy {
                min_canary_duration_secs: 0,
                max_canary_duration_secs: 300,
                ..CanaryPolicy::default()
            });

        record.state = LifecycleState::Canary;
        record.deployed_at = base - chrono::Duration::seconds(120);
        record.transitions.clear();
        assert_eq!(record.canary_expires_in_secs_at(base), Some(180));

        record.deployed_at = base - chrono::Duration::seconds(360);
        assert_eq!(record.canary_expires_in_secs_at(base), Some(0));

        record.state = LifecycleState::Production;
        assert_eq!(record.canary_expires_in_secs_at(base), None);
    }

    #[test]
    fn lifecycle_status_from_record_includes_crash_and_rollback_signals() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0))
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(1)
                    .with_min_canary_duration(0),
            );
        record.state = LifecycleState::Canary;
        record.deployed_at = now - chrono::Duration::seconds(10);
        record.update_health(false, Some(250));

        let status = LifecycleStatus::from_record(&record, now, true);
        assert!(status.crash_loop_detected);
        assert_eq!(
            status.rollback_target_version,
            Some(semver::Version::new(0, 9, 0))
        );
        assert!(status.auto_rollback_pending);
        assert_eq!(status.canary_expires_in_secs, Some(3590));
    }

    #[test]
    fn transition_reason_serde_roundtrip() {
        let reasons = [
            TransitionReason::InstallComplete,
            TransitionReason::ManualPromotion,
            TransitionReason::AutoPromotion { health_score: 95 },
            TransitionReason::ManualRollback {
                reason: Some("test".to_string()),
            },
            TransitionReason::AutoRollback {
                health_score: 70,
                failure_reason: "error".to_string(),
            },
            TransitionReason::NewVersion {
                from_version: "1.0.0".to_string(),
                to_version: "1.1.0".to_string(),
            },
        ];

        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let decoded: TransitionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, decoded);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleTransition additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_transition_new_and_clone() {
        let t = LifecycleTransition::new(
            LifecycleState::Pending,
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        );
        assert_eq!(t.from, LifecycleState::Pending);
        assert_eq!(t.to, LifecycleState::Installing);
        assert!(t.initiated_by.is_none());

        let cloned = t.clone();
        assert_eq!(t, cloned);
    }

    #[test]
    fn lifecycle_transition_serde_roundtrip() {
        let t = LifecycleTransition::new(
            LifecycleState::Canary,
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .with_initiator("admin@example.com");

        let json = serde_json::to_string(&t).unwrap();
        let back: LifecycleTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from, LifecycleState::Canary);
        assert_eq!(back.to, LifecycleState::Production);
        assert_eq!(back.initiated_by, Some("admin@example.com".into()));
    }

    #[test]
    fn lifecycle_transition_equality() {
        let a = LifecycleTransition::new(
            LifecycleState::Pending,
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        );
        let b = LifecycleTransition::new(
            LifecycleState::Pending,
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        );
        // timestamp will differ but from/to/reason should be equal
        assert_eq!(a.from, b.from);
        assert_eq!(a.to, b.to);
        assert_eq!(a.reason, b.reason);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TransitionReason Display coverage for all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transition_reason_display_disabled() {
        let r = TransitionReason::Disabled {
            reason: "maintenance".into(),
        };
        assert!(r.to_string().contains("disabled"));
        assert!(r.to_string().contains("maintenance"));
    }

    #[test]
    fn transition_reason_display_uninstalled() {
        assert_eq!(TransitionReason::Uninstalled.to_string(), "uninstalled");
    }

    #[test]
    fn transition_reason_clone() {
        let r = TransitionReason::AutoPromotion { health_score: 99 };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HealthMetrics additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_metrics_clone() {
        let m = HealthMetrics::default();
        let cloned = m;
        assert_eq!(cloned.successes, 0);
        assert_eq!(cloned.success_rate, 100);
    }

    #[test]
    fn health_metrics_serde_roundtrip() {
        let m = HealthMetrics {
            successes: 100,
            failures: 5,
            samples: 105,
            success_rate: 95,
            total_latency_ms: 21000,
            latency_samples: 105,
            max_latency_ms: 500,
            last_updated: Utc::now(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: HealthMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.successes, 100);
        assert_eq!(back.failures, 5);
        assert_eq!(back.samples, 105);
        assert_eq!(back.success_rate, 95);
        assert_eq!(back.total_latency_ms, 21000);
        assert_eq!(back.latency_samples, 105);
        assert_eq!(back.max_latency_ms, 500);
    }

    #[test]
    fn health_metrics_avg_latency_with_samples() {
        let m = HealthMetrics {
            total_latency_ms: 1000,
            samples: 10,
            latency_samples: 10,
            ..Default::default()
        };
        assert_eq!(m.avg_latency_ms(), Some(100));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CrashLoopDetector additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crash_loop_detector_default() {
        let mut d = CrashLoopDetector::default();
        assert_eq!(d.max_crashes, 5);
        assert_eq!(d.window_secs, 300);
        assert!(!d.is_crash_loop(Utc::now()));
    }

    #[test]
    fn crash_loop_detector_clone() {
        let mut d = CrashLoopDetector::new(3, 60);
        d.record_crash(Utc::now());
        let mut cloned = d.clone();
        assert_eq!(cloned.max_crashes, 3);
        assert_eq!(cloned.crash_count_in_window(Utc::now()), 1);
    }

    #[test]
    fn crash_loop_detector_serde_roundtrip() {
        let mut d = CrashLoopDetector::new(3, 120);
        d.record_crash(Utc::now());
        d.record_crash(Utc::now());
        let json = serde_json::to_string(&d).unwrap();
        let back: CrashLoopDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_crashes, 3);
        assert_eq!(back.window_secs, 120);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleError additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_error_clone_and_eq() {
        let a = LifecycleError::NoRollbackTarget;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn lifecycle_error_invalid_policy_display() {
        let err = LifecycleError::InvalidPolicy {
            reason: "threshold too high".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid canary policy"));
        assert!(msg.contains("threshold too high"));
    }

    #[test]
    fn lifecycle_error_not_found_display() {
        let err = LifecycleError::NotFound {
            connector_id: test_connector_id(),
        };
        let msg = err.to_string();
        assert!(msg.contains("connector not found"));
    }

    #[test]
    fn lifecycle_error_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(LifecycleError::NoRollbackTarget);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn lifecycle_error_inequality() {
        let a = LifecycleError::NoRollbackTarget;
        let b = LifecycleError::InvalidPolicy {
            reason: "bad".into(),
        };
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleStatus additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_status_clone() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        let cloned = status;
        assert_eq!(cloned.state, LifecycleState::Pending);
        assert!(!cloned.crash_loop_detected);
    }

    #[test]
    fn lifecycle_status_serde_roundtrip() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        let json = serde_json::to_string(&status).unwrap();
        let back: LifecycleStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, LifecycleState::Pending);
        assert!(!back.auto_promote_pending);
        assert!(!back.auto_rollback_pending);
        assert!(!back.crash_loop_detected);
    }

    #[test]
    fn lifecycle_status_from_record_no_crash_no_rollback() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert!(!status.auto_promote_pending);
        assert!(!status.auto_rollback_pending);
        assert!(status.canary_expires_in_secs.is_none());
        assert!(status.rollback_target_version.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleState Hash + Copy
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_state_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LifecycleState::Pending);
        set.insert(LifecycleState::Canary);
        set.insert(LifecycleState::Pending); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn lifecycle_state_copy() {
        let a = LifecycleState::Production;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleRecord serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_record_serde_roundtrip() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let json = serde_json::to_string(&record).unwrap();
        let back: LifecycleRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id.as_str(), "test:lifecycle:v1");
        assert_eq!(back.version, semver::Version::new(1, 0, 0));
        assert_eq!(back.state, LifecycleState::Pending);
    }

    #[test]
    fn lifecycle_record_clone() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let cloned = record.clone();
        assert_eq!(cloned.connector_id.as_str(), record.connector_id.as_str());
        assert_eq!(cloned.state, record.state);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CanaryPolicy Clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_policy_clone() {
        let policy = CanaryPolicy::default();
        let cloned = policy.clone();
        assert_eq!(cloned.promotion_threshold, policy.promotion_threshold);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Comprehensive Invalid Transition Matrix
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invalid_transition_pending_to_canary() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        assert!(
            record
                .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_pending_to_production() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        assert!(
            record
                .transition(
                    LifecycleState::Production,
                    TransitionReason::ManualPromotion
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_pending_to_rolled_back() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        assert!(
            record
                .transition(
                    LifecycleState::RolledBack,
                    TransitionReason::ManualRollback { reason: None },
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_pending_to_disabled() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        assert!(
            record
                .transition(
                    LifecycleState::Disabled,
                    TransitionReason::Disabled {
                        reason: "test".into(),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_installing_to_production() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::Production,
                    TransitionReason::ManualPromotion
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_installing_to_rolled_back() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::RolledBack,
                    TransitionReason::ManualRollback { reason: None },
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_installing_to_disabled() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::Disabled,
                    TransitionReason::Disabled {
                        reason: "test".into(),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_production_to_installing() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::Installing,
                    TransitionReason::InstallComplete
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_production_to_pending() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();
        assert!(
            record
                .transition(LifecycleState::Pending, TransitionReason::InstallComplete)
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_rolled_back_to_production() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::ManualRollback { reason: None },
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::Production,
                    TransitionReason::ManualPromotion
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_rolled_back_to_installing() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::ManualRollback { reason: None },
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::Installing,
                    TransitionReason::InstallComplete
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_disabled_to_production() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "test".into(),
                },
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::Production,
                    TransitionReason::ManualPromotion
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_disabled_to_rolled_back() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "test".into(),
                },
            )
            .unwrap();
        assert!(
            record
                .transition(
                    LifecycleState::RolledBack,
                    TransitionReason::ManualRollback { reason: None },
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_transition_uninstalled_to_anything() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
            .unwrap();

        for target in [
            LifecycleState::Pending,
            LifecycleState::Installing,
            LifecycleState::Canary,
            LifecycleState::Production,
            LifecycleState::RolledBack,
            LifecycleState::Disabled,
        ] {
            assert!(
                record
                    .transition(target, TransitionReason::InstallComplete)
                    .is_err(),
                "Uninstalled -> {target} should be invalid"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Valid Transition Edges (less obvious paths)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn valid_transition_production_to_canary_on_new_version() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.0".into(),
                    to_version: "2.0.0".into(),
                },
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::Canary);
    }

    #[test]
    fn valid_transition_disabled_to_canary_reenable() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "maintenance".into(),
                },
            )
            .unwrap();
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.0".into(),
                    to_version: "1.0.1".into(),
                },
            )
            .unwrap();
        assert_eq!(record.state, LifecycleState::Canary);
    }

    #[test]
    fn valid_transition_all_states_to_uninstalled() {
        for start_state in [
            LifecycleState::Installing,
            LifecycleState::Canary,
            LifecycleState::Production,
            LifecycleState::RolledBack,
            LifecycleState::Disabled,
        ] {
            let mut record = LifecycleRecord::new(test_connector_id(), test_version());
            // Get to the desired state first
            match start_state {
                LifecycleState::Installing => {
                    record
                        .transition(
                            LifecycleState::Installing,
                            TransitionReason::InstallComplete,
                        )
                        .unwrap();
                }
                LifecycleState::Canary => {
                    record
                        .transition(
                            LifecycleState::Installing,
                            TransitionReason::InstallComplete,
                        )
                        .unwrap();
                    record
                        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
                        .unwrap();
                }
                LifecycleState::Production => {
                    record
                        .transition(
                            LifecycleState::Installing,
                            TransitionReason::InstallComplete,
                        )
                        .unwrap();
                    record
                        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
                        .unwrap();
                    record
                        .transition(
                            LifecycleState::Production,
                            TransitionReason::ManualPromotion,
                        )
                        .unwrap();
                }
                LifecycleState::RolledBack => {
                    record
                        .transition(
                            LifecycleState::Installing,
                            TransitionReason::InstallComplete,
                        )
                        .unwrap();
                    record
                        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
                        .unwrap();
                    record
                        .transition(
                            LifecycleState::RolledBack,
                            TransitionReason::ManualRollback { reason: None },
                        )
                        .unwrap();
                }
                LifecycleState::Disabled => {
                    record
                        .transition(
                            LifecycleState::Installing,
                            TransitionReason::InstallComplete,
                        )
                        .unwrap();
                    record
                        .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
                        .unwrap();
                    record
                        .transition(
                            LifecycleState::Disabled,
                            TransitionReason::Disabled {
                                reason: "test".into(),
                            },
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(record.state, start_state);
            record
                .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
                .unwrap();
            assert_eq!(record.state, LifecycleState::Uninstalled);
        }
    }

    #[test]
    fn valid_transition_pending_to_uninstalled() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
            .unwrap();
        assert_eq!(record.state, LifecycleState::Uninstalled);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CrashLoopDetector Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crash_loop_detector_negative_window_clears_all() {
        let mut detector = CrashLoopDetector::new(3, -1);
        let now = Utc::now();
        detector.record_crash(now);
        detector.record_crash(now);
        detector.record_crash(now);
        // Negative window causes prune_old to clear everything
        assert!(!detector.is_crash_loop(now));
    }

    #[test]
    fn crash_loop_detector_zero_window() {
        let mut detector = CrashLoopDetector::new(3, 0);
        let now = Utc::now();
        detector.record_crash(now);
        detector.record_crash(now);
        detector.record_crash(now);
        // Window of 0 means cutoff = now, crashes at exactly cutoff are pruned (< cutoff)
        assert_eq!(detector.crash_count_in_window(now), 3);
    }

    #[test]
    fn crash_loop_detector_exact_boundary_retained() {
        let mut detector = CrashLoopDetector::new(3, 60);
        let base = Utc::now();
        // Crash exactly at the boundary (now - window_secs) is retained (< not <=)
        let at_boundary = base - chrono::Duration::seconds(60);
        detector.record_crash(at_boundary);
        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base);
        assert_eq!(detector.crash_count_in_window(base), 3);
    }

    #[test]
    fn crash_loop_detector_just_outside_boundary_pruned() {
        let mut detector = CrashLoopDetector::new(3, 60);
        let base = Utc::now();
        // Crash 61 seconds ago is outside the window and pruned
        detector.record_crash(base - chrono::Duration::seconds(61));
        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base);
        assert_eq!(detector.crash_count_in_window(base), 2);
    }

    #[test]
    fn crash_loop_detector_just_inside_window() {
        let mut detector = CrashLoopDetector::new(3, 60);
        let base = Utc::now();
        // 59 seconds ago — just inside the window
        detector.record_crash(base - chrono::Duration::seconds(59));
        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base);
        assert_eq!(detector.crash_count_in_window(base), 3);
        assert!(detector.is_crash_loop(base));
    }

    #[test]
    fn crash_loop_detector_empty_is_not_loop() {
        let mut detector = CrashLoopDetector::new(3, 60);
        assert!(!detector.is_crash_loop(Utc::now()));
        assert_eq!(detector.crash_count_in_window(Utc::now()), 0);
    }

    #[test]
    fn crash_loop_detector_one_crash_max_one() {
        let mut detector = CrashLoopDetector::new(1, 60);
        let now = Utc::now();
        detector.record_crash(now);
        assert!(detector.is_crash_loop(now));
    }

    #[test]
    fn crash_loop_detector_success_clears_all_history() {
        let mut detector = CrashLoopDetector::new(5, 300);
        let now = Utc::now();
        for i in 0..4 {
            detector.record_crash(now - chrono::Duration::seconds(i));
        }
        assert_eq!(detector.crash_count_in_window(now), 4);
        detector.record_success();
        assert_eq!(detector.crash_count_in_window(now), 0);
    }

    #[test]
    fn crash_loop_detector_large_threshold() {
        let mut detector = CrashLoopDetector::new(1000, 60);
        let now = Utc::now();
        for i in 0..999 {
            detector.record_crash(now - chrono::Duration::milliseconds(i));
        }
        assert!(!detector.is_crash_loop(now));
        detector.record_crash(now);
        assert!(detector.is_crash_loop(now));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Version Tracking Through Rollback/Upgrade
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn previous_version_preserved_through_rollback() {
        let prev = semver::Version::new(0, 9, 0);
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(prev.clone());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::AutoRollback {
                    health_score: 50,
                    failure_reason: "bad health".into(),
                },
            )
            .unwrap();
        assert_eq!(record.previous_version.as_ref(), Some(&prev));
    }

    #[test]
    fn version_tracks_current_deployment() {
        let record = LifecycleRecord::new(test_connector_id(), semver::Version::new(2, 3, 4));
        assert_eq!(record.version, semver::Version::new(2, 3, 4));
    }

    #[test]
    fn crash_and_maybe_rollback_needs_previous_version() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        let mut detector = CrashLoopDetector::new(2, 60);
        let now = Utc::now();

        // Reach crash loop threshold
        detector.record_crash(now);
        // Use record_crash_and_maybe_rollback for the second crash
        let result = record.record_crash_and_maybe_rollback(&mut detector, now, "crash");
        assert!(matches!(result, Err(LifecycleError::NoRollbackTarget)));
    }

    #[test]
    fn crash_and_maybe_rollback_succeeds_with_previous_version() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        let mut detector = CrashLoopDetector::new(2, 60);
        let now = Utc::now();
        detector.record_crash(now);
        let rolled_back =
            record.record_crash_and_maybe_rollback(&mut detector, now, "second crash");
        assert!(rolled_back.unwrap());
        assert_eq!(record.state, LifecycleState::RolledBack);
    }

    #[test]
    fn crash_and_maybe_rollback_resets_detector_after_rollback() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        let mut detector = CrashLoopDetector::new(2, 60);
        let now = Utc::now();
        detector.record_crash(now);
        record
            .record_crash_and_maybe_rollback(&mut detector, now, "crash")
            .unwrap();

        // Detector should be reset after successful rollback
        assert_eq!(detector.crash_count_in_window(now), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Health Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_metrics_all_failures() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        for _ in 0..10 {
            record.update_health(false, Some(500));
        }
        assert_eq!(record.health.success_rate, 0);
        assert_eq!(record.health.failures, 10);
        assert_eq!(record.health.successes, 0);
    }

    #[test]
    fn health_metrics_all_successes() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        for _ in 0..10 {
            record.update_health(true, Some(50));
        }
        assert_eq!(record.health.success_rate, 100);
        assert_eq!(record.health.successes, 10);
        assert_eq!(record.health.failures, 0);
    }

    #[test]
    fn health_metrics_single_failure_rate() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(false, Some(100));
        assert_eq!(record.health.success_rate, 0);
        assert_eq!(record.health.samples, 1);
    }

    #[test]
    fn health_metrics_single_success_rate() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(100));
        assert_eq!(record.health.success_rate, 100);
        assert_eq!(record.health.samples, 1);
    }

    #[test]
    fn health_metrics_latency_tracking_without_latency() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, None);
        record.update_health(true, None);
        assert_eq!(record.health.total_latency_ms, 0);
        assert_eq!(record.health.max_latency_ms, 0);
        assert_eq!(record.health.latency_samples, 0);
        // No latency data provided, so average should be None (not Some(0))
        assert!(record.health.avg_latency_ms().is_none());
    }

    #[test]
    fn health_metrics_max_latency_tracks_highest() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(100));
        record.update_health(true, Some(500));
        record.update_health(true, Some(200));
        assert_eq!(record.health.max_latency_ms, 500);
    }

    #[test]
    fn health_metrics_avg_latency_calculation() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(100));
        record.update_health(true, Some(200));
        record.update_health(true, Some(300));
        // Total: 600, samples: 3, avg: 200
        assert_eq!(record.health.avg_latency_ms(), Some(200));
    }

    #[test]
    fn health_reset_clears_all_metrics() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        for _ in 0..50 {
            record.update_health(true, Some(100));
        }
        record.reset_health();
        assert_eq!(record.health.samples, 0);
        assert_eq!(record.health.successes, 0);
        assert_eq!(record.health.failures, 0);
        assert_eq!(record.health.total_latency_ms, 0);
        assert_eq!(record.health.max_latency_ms, 0);
        // Default success_rate is 100 (optimistic)
        assert_eq!(record.health.success_rate, 100);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canary Duration Gating
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn should_not_auto_promote_before_min_duration() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_promotion_threshold(90)
                    .with_min_samples(5)
                    .with_min_canary_duration(600), // 10 minutes
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        for _ in 0..10 {
            record.update_health(true, Some(50));
        }
        // Health is great but canary just started — should NOT promote
        assert!(!record.should_auto_promote());
    }

    #[test]
    fn should_auto_promote_after_min_duration() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_promotion_threshold(90)
                    .with_min_samples(5)
                    .with_min_canary_duration(60),
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        for _ in 0..10 {
            record.update_health(true, Some(50));
        }
        // Check at a time 120 seconds in the future
        let future = Utc::now() + chrono::Duration::seconds(120);
        assert!(record.should_auto_promote_at(future));
    }

    #[test]
    fn canary_expires_in_secs_returns_none_when_not_canary() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        assert!(record.canary_expires_in_secs_at(Utc::now()).is_none());
    }

    #[test]
    fn canary_expires_in_secs_returns_max_when_just_entered() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy::new());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let remaining = record.canary_expires_in_secs_at(Utc::now());
        assert!(remaining.is_some());
        // Should be close to max (3600) — allow 5 second tolerance
        let secs = remaining.unwrap();
        assert!(secs >= 3595, "expected ~3600, got {secs}");
    }

    #[test]
    fn canary_expires_in_secs_returns_zero_when_exceeded() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy::new());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // Check 2 hours in the future (well past 1hr max)
        let future = Utc::now() + chrono::Duration::seconds(7200);
        assert_eq!(record.canary_expires_in_secs_at(future), Some(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Auto-Rollback Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn auto_rollback_not_triggered_below_min_samples() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(100),
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // Add 10 failures (0% success rate but only 10 samples)
        for _ in 0..10 {
            record.update_health(false, Some(500));
        }
        assert_eq!(record.health.success_rate, 0);
        assert!(
            !record.should_auto_rollback(),
            "should not rollback before min_samples"
        );
    }

    #[test]
    fn auto_rollback_triggered_at_exact_threshold() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(10),
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // 79% success rate (just below 80% threshold)
        for _ in 0..79 {
            record.update_health(true, Some(50));
        }
        for _ in 0..21 {
            record.update_health(false, Some(500));
        }
        assert_eq!(record.health.success_rate, 79);
        assert!(record.should_auto_rollback());
    }

    #[test]
    fn auto_rollback_not_triggered_when_exactly_at_threshold() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(10),
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // Exactly 80% success rate (at threshold, not below)
        for _ in 0..80 {
            record.update_health(true, Some(50));
        }
        for _ in 0..20 {
            record.update_health(false, Some(500));
        }
        assert_eq!(record.health.success_rate, 80);
        assert!(!record.should_auto_rollback());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleStatus Comprehensive
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_status_from_record_in_canary_with_auto_promote() {
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
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        for _ in 0..10 {
            record.update_health(true, Some(50));
        }
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert!(status.auto_promote_pending);
        assert!(!status.auto_rollback_pending);
        assert!(!status.crash_loop_detected);
        assert_eq!(
            status.rollback_target_version,
            Some(semver::Version::new(0, 9, 0))
        );
    }

    #[test]
    fn lifecycle_status_from_record_in_canary_with_auto_rollback() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(10),
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        for _ in 0..10 {
            record.update_health(false, Some(500));
        }
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert!(!status.auto_promote_pending);
        assert!(status.auto_rollback_pending);
    }

    #[test]
    fn lifecycle_status_crash_loop_implies_auto_rollback() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_rollback_threshold(80)
                    .with_min_samples(1000),
            );
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // Health is fine, but crash loop detected externally
        for _ in 0..5 {
            record.update_health(true, Some(50));
        }
        let status = LifecycleStatus::from_record(&record, Utc::now(), true);
        assert!(status.crash_loop_detected);
        assert!(status.auto_rollback_pending);
    }

    #[test]
    fn lifecycle_status_in_production_no_canary_expiry() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert!(status.canary_expires_in_secs.is_none());
        assert_eq!(status.state, LifecycleState::Production);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canary Policy Validation Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_policy_equal_thresholds_invalid() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(90)
            .with_rollback_threshold(90);
        assert!(policy.validate().is_err());
    }

    #[test]
    fn canary_policy_min_greater_than_max_duration_invalid() {
        let mut policy = CanaryPolicy::new();
        policy.min_canary_duration_secs = 7200;
        policy.max_canary_duration_secs = 3600;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn canary_policy_zero_traffic_valid() {
        let policy = CanaryPolicy::new().with_canary_traffic_percent(0);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_100_traffic_valid() {
        let policy = CanaryPolicy::new().with_canary_traffic_percent(100);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_101_traffic_invalid() {
        let policy = CanaryPolicy::new().with_canary_traffic_percent(101);
        assert!(policy.validate().is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transition Audit Trail Integrity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transition_records_correct_from_and_to() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        let t = &record.transitions[0];
        assert_eq!(t.from, LifecycleState::Pending);
        assert_eq!(t.to, LifecycleState::Installing);
    }

    #[test]
    fn transition_records_correct_reason() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::AutoPromotion { health_score: 98 },
            )
            .unwrap();
        assert!(matches!(
            &record.transitions[2].reason,
            TransitionReason::AutoPromotion { health_score: 98 }
        ));
    }

    #[test]
    fn failed_transition_does_not_add_to_audit_trail() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        let _ = record.transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        );
        assert!(record.transitions.is_empty());
        assert_eq!(record.state, LifecycleState::Pending);
    }

    #[test]
    fn state_changed_at_updates_on_transition() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        let before = record.state_changed_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        assert!(record.state_changed_at >= before);
    }
}
