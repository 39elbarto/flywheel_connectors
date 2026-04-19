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
            let rate =
                (self.health.successes as f64 / self.health.samples as f64 * 100.0).min(100.0);
            self.health.success_rate = rate.round() as u8;
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
// Type-state lifecycle markers (C3.3)
// ─────────────────────────────────────────────────────────────────────────────

/// Marker: connector is pending deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatePending;
/// Marker: connector is being installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateInstalling;
/// Marker: connector is in canary rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateCanary;
/// Marker: connector is in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateProduction;
/// Marker: connector was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateRolledBack;
/// Marker: connector is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDisabled;
/// Marker: connector is uninstalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateUninstalled;

/// Sealed trait for valid lifecycle state markers.
mod lifecycle_sealed {
    pub trait LifecycleMarker {
        /// The corresponding runtime [`super::LifecycleState`] variant.
        fn runtime_state() -> super::LifecycleState;
    }
}

impl lifecycle_sealed::LifecycleMarker for StatePending {
    fn runtime_state() -> LifecycleState { LifecycleState::Pending }
}
impl lifecycle_sealed::LifecycleMarker for StateInstalling {
    fn runtime_state() -> LifecycleState { LifecycleState::Installing }
}
impl lifecycle_sealed::LifecycleMarker for StateCanary {
    fn runtime_state() -> LifecycleState { LifecycleState::Canary }
}
impl lifecycle_sealed::LifecycleMarker for StateProduction {
    fn runtime_state() -> LifecycleState { LifecycleState::Production }
}
impl lifecycle_sealed::LifecycleMarker for StateRolledBack {
    fn runtime_state() -> LifecycleState { LifecycleState::RolledBack }
}
impl lifecycle_sealed::LifecycleMarker for StateDisabled {
    fn runtime_state() -> LifecycleState { LifecycleState::Disabled }
}
impl lifecycle_sealed::LifecycleMarker for StateUninstalled {
    fn runtime_state() -> LifecycleState { LifecycleState::Uninstalled }
}

/// A type-state lifecycle record where the state `S` is encoded at the
/// type level. Invalid transitions are compile errors.
///
/// Use [`TypedLifecycleRecord::new`] to start in [`StatePending`], then
/// call transition methods (e.g., [`start_install`]) that consume `self`
/// and return a new record in the target state.
///
/// For heterogeneous storage, erase to [`AnyLifecycleRecord`] via
/// [`TypedLifecycleRecord::erase`].
///
/// [`start_install`]: TypedLifecycleRecord::<StatePending>::start_install
#[derive(Debug, Clone)]
pub struct TypedLifecycleRecord<S: lifecycle_sealed::LifecycleMarker> {
    inner: LifecycleRecord,
    _state: std::marker::PhantomData<S>,
}

impl<S: lifecycle_sealed::LifecycleMarker> TypedLifecycleRecord<S> {
    /// The current runtime lifecycle state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        S::runtime_state()
    }

    /// Access the underlying [`LifecycleRecord`].
    #[must_use]
    pub const fn record(&self) -> &LifecycleRecord {
        &self.inner
    }

    /// Erase the type-state for dynamic dispatch / heterogeneous storage.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // LifecycleRecord has Drop
    pub fn erase(self) -> AnyLifecycleRecord {
        AnyLifecycleRecord { inner: self.inner }
    }

    fn transition_to<T: lifecycle_sealed::LifecycleMarker>(
        mut self,
        reason: TransitionReason,
    ) -> TypedLifecycleRecord<T> {
        // The transition is guaranteed valid by the type system — skip
        // runtime validation. We still record the audit trail.
        let transition = LifecycleTransition::new(self.inner.state, T::runtime_state(), reason);
        self.inner.transitions.push(transition);
        self.inner.state = T::runtime_state();
        self.inner.state_changed_at = Utc::now();
        TypedLifecycleRecord {
            inner: self.inner,
            _state: std::marker::PhantomData,
        }
    }
}

// Pending -> Installing | Uninstalled
impl TypedLifecycleRecord<StatePending> {
    /// Create a new pending deployment record.
    #[must_use]
    pub fn new(connector_id: ConnectorId, version: semver::Version) -> Self {
        Self {
            inner: LifecycleRecord::new(connector_id, version),
            _state: std::marker::PhantomData,
        }
    }

    /// Begin installation.
    #[must_use]
    pub fn start_install(self, reason: TransitionReason) -> TypedLifecycleRecord<StateInstalling> {
        self.transition_to(reason)
    }

    /// Uninstall before ever deploying.
    #[must_use]
    pub fn uninstall(self, reason: TransitionReason) -> TypedLifecycleRecord<StateUninstalled> {
        self.transition_to(reason)
    }
}

// Installing -> Canary | Uninstalled
impl TypedLifecycleRecord<StateInstalling> {
    /// Move to canary rollout after installation.
    #[must_use]
    pub fn start_canary(self, reason: TransitionReason) -> TypedLifecycleRecord<StateCanary> {
        self.transition_to(reason)
    }

    /// Uninstall during installation.
    #[must_use]
    pub fn uninstall(self, reason: TransitionReason) -> TypedLifecycleRecord<StateUninstalled> {
        self.transition_to(reason)
    }
}

// Canary -> Production | RolledBack | Disabled | Uninstalled
impl TypedLifecycleRecord<StateCanary> {
    /// Promote to production.
    #[must_use]
    pub fn promote(self, reason: TransitionReason) -> TypedLifecycleRecord<StateProduction> {
        self.transition_to(reason)
    }

    /// Roll back from canary.
    #[must_use]
    pub fn rollback(self, reason: TransitionReason) -> TypedLifecycleRecord<StateRolledBack> {
        self.transition_to(reason)
    }

    /// Disable from canary.
    #[must_use]
    pub fn disable(self, reason: TransitionReason) -> TypedLifecycleRecord<StateDisabled> {
        self.transition_to(reason)
    }

    /// Uninstall from canary.
    #[must_use]
    pub fn uninstall(self, reason: TransitionReason) -> TypedLifecycleRecord<StateUninstalled> {
        self.transition_to(reason)
    }
}

// Production -> Canary | RolledBack | Disabled | Uninstalled
impl TypedLifecycleRecord<StateProduction> {
    /// Re-enter canary (e.g., for a new version).
    #[must_use]
    pub fn to_canary(self, reason: TransitionReason) -> TypedLifecycleRecord<StateCanary> {
        self.transition_to(reason)
    }

    /// Roll back from production.
    #[must_use]
    pub fn rollback(self, reason: TransitionReason) -> TypedLifecycleRecord<StateRolledBack> {
        self.transition_to(reason)
    }

    /// Disable in production.
    #[must_use]
    pub fn disable(self, reason: TransitionReason) -> TypedLifecycleRecord<StateDisabled> {
        self.transition_to(reason)
    }

    /// Uninstall from production.
    #[must_use]
    pub fn uninstall(self, reason: TransitionReason) -> TypedLifecycleRecord<StateUninstalled> {
        self.transition_to(reason)
    }
}

// RolledBack -> Canary | Disabled | Uninstalled
impl TypedLifecycleRecord<StateRolledBack> {
    /// Re-enter canary after rollback.
    #[must_use]
    pub fn to_canary(self, reason: TransitionReason) -> TypedLifecycleRecord<StateCanary> {
        self.transition_to(reason)
    }

    /// Disable after rollback.
    #[must_use]
    pub fn disable(self, reason: TransitionReason) -> TypedLifecycleRecord<StateDisabled> {
        self.transition_to(reason)
    }

    /// Uninstall after rollback.
    #[must_use]
    pub fn uninstall(self, reason: TransitionReason) -> TypedLifecycleRecord<StateUninstalled> {
        self.transition_to(reason)
    }
}

// Disabled -> Canary | Uninstalled
impl TypedLifecycleRecord<StateDisabled> {
    /// Re-enter canary from disabled.
    #[must_use]
    pub fn to_canary(self, reason: TransitionReason) -> TypedLifecycleRecord<StateCanary> {
        self.transition_to(reason)
    }

    /// Uninstall from disabled.
    #[must_use]
    pub fn uninstall(self, reason: TransitionReason) -> TypedLifecycleRecord<StateUninstalled> {
        self.transition_to(reason)
    }
}

// Uninstalled is a terminal state — no transitions out.

/// Type-erased lifecycle record for heterogeneous storage.
///
/// Created from any [`TypedLifecycleRecord<S>`] via [`erase()`].
/// The runtime state is preserved in the inner [`LifecycleRecord`].
///
/// [`erase()`]: TypedLifecycleRecord::erase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyLifecycleRecord {
    inner: LifecycleRecord,
}

impl AnyLifecycleRecord {
    /// The current runtime state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.inner.state
    }

    /// Access the underlying record.
    #[must_use]
    pub const fn record(&self) -> &LifecycleRecord {
        &self.inner
    }

    /// Convert from an existing runtime record.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn from_record(record: LifecycleRecord) -> Self {
        Self { inner: record }
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

    /// Lifecycle state could not be persisted durably.
    Persistence {
        /// Reason persistence failed.
        reason: String,
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
            Self::Persistence { reason } => {
                write!(f, "failed to persist lifecycle state: {reason}")
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

        let err = LifecycleError::Persistence {
            reason: "disk full".into(),
        };
        assert!(err.to_string().contains("disk full"));

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
    fn lifecycle_error_persistence_display() {
        let err = LifecycleError::Persistence {
            reason: "permission denied".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("persist"));
        assert!(msg.contains("permission denied"));
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

    // ─────────────────────────────────────────────────────────────────────────
    // Exhaustive State Transition Matrix
    // ─────────────────────────────────────────────────────────────────────────

    /// All 7 lifecycle states for exhaustive enumeration.
    const ALL_STATES: [LifecycleState; 7] = [
        LifecycleState::Pending,
        LifecycleState::Installing,
        LifecycleState::Canary,
        LifecycleState::Production,
        LifecycleState::RolledBack,
        LifecycleState::Disabled,
        LifecycleState::Uninstalled,
    ];

    /// Valid transitions as defined by the state machine.
    const VALID_TRANSITIONS: &[(LifecycleState, LifecycleState)] = &[
        // Pending -> Installing/Uninstalled
        (LifecycleState::Pending, LifecycleState::Installing),
        (LifecycleState::Pending, LifecycleState::Uninstalled),
        // Installing -> Canary/Uninstalled
        (LifecycleState::Installing, LifecycleState::Canary),
        (LifecycleState::Installing, LifecycleState::Uninstalled),
        // Canary -> Production/RolledBack/Disabled/Uninstalled
        (LifecycleState::Canary, LifecycleState::Production),
        (LifecycleState::Canary, LifecycleState::RolledBack),
        (LifecycleState::Canary, LifecycleState::Disabled),
        (LifecycleState::Canary, LifecycleState::Uninstalled),
        // Production -> Canary/RolledBack/Disabled/Uninstalled
        (LifecycleState::Production, LifecycleState::Canary),
        (LifecycleState::Production, LifecycleState::RolledBack),
        (LifecycleState::Production, LifecycleState::Disabled),
        (LifecycleState::Production, LifecycleState::Uninstalled),
        // RolledBack -> Canary/Disabled/Uninstalled
        (LifecycleState::RolledBack, LifecycleState::Canary),
        (LifecycleState::RolledBack, LifecycleState::Disabled),
        (LifecycleState::RolledBack, LifecycleState::Uninstalled),
        // Disabled -> Canary/Uninstalled
        (LifecycleState::Disabled, LifecycleState::Canary),
        (LifecycleState::Disabled, LifecycleState::Uninstalled),
    ];

    fn is_valid_transition(from: LifecycleState, to: LifecycleState) -> bool {
        VALID_TRANSITIONS.iter().any(|&(f, t)| f == from && t == to)
    }

    #[test]
    fn exhaustive_transition_matrix_valid_pairs_succeed() {
        for &(from, to) in VALID_TRANSITIONS {
            let mut record = LifecycleRecord::new(test_connector_id(), test_version());
            // Force state to `from` (bypass validation for test setup)
            record.state = from;
            let result = record.transition(to, TransitionReason::InstallComplete);
            assert!(
                result.is_ok(),
                "expected {from} -> {to} to succeed, but got {result:?}",
            );
            assert_eq!(record.state, to);
        }
    }

    #[test]
    fn exhaustive_transition_matrix_invalid_pairs_rejected() {
        let mut rejected_count = 0;
        for &from in &ALL_STATES {
            for &to in &ALL_STATES {
                if from == to || is_valid_transition(from, to) {
                    continue;
                }
                let mut record = LifecycleRecord::new(test_connector_id(), test_version());
                record.state = from;
                let result = record.transition(to, TransitionReason::InstallComplete);
                assert!(
                    result.is_err(),
                    "expected {from} -> {to} to be rejected, but it succeeded",
                );
                assert_eq!(
                    record.state, from,
                    "state should not change after rejected transition"
                );
                rejected_count += 1;
            }
        }
        // 7*7=49 pairs, minus 7 self-transitions, minus 17 valid = 25 invalid
        assert!(
            rejected_count >= 25,
            "expected at least 25 rejected pairs, got {rejected_count}"
        );
    }

    #[test]
    fn self_transitions_all_rejected() {
        for &state in &ALL_STATES {
            let mut record = LifecycleRecord::new(test_connector_id(), test_version());
            record.state = state;
            let result = record.transition(state, TransitionReason::InstallComplete);
            assert!(
                result.is_err(),
                "self-transition {state} -> {state} should be rejected"
            );
        }
    }

    #[test]
    fn uninstalled_is_terminal_state() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Uninstalled;
        for &to in &ALL_STATES {
            let result = record.transition(to, TransitionReason::InstallComplete);
            assert!(
                result.is_err(),
                "uninstalled -> {to} should be rejected (terminal state)"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Crash Loop + Rollback Integration
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crash_loop_detector_default_values() {
        let detector = CrashLoopDetector::default();
        assert_eq!(detector.max_crashes, 5);
        assert_eq!(detector.window_secs, 300);
    }

    #[test]
    fn crash_loop_detector_negative_window_clears_crashes() {
        let mut detector = CrashLoopDetector::new(3, -1);
        let now = Utc::now();
        detector.record_crash(now);
        detector.record_crash(now);
        detector.record_crash(now);
        // Negative window clears all crashes
        assert!(!detector.is_crash_loop(now));
    }

    #[test]
    fn crash_loop_detector_zero_threshold() {
        let mut detector = CrashLoopDetector::new(0, 300);
        let now = Utc::now();
        // 0 threshold means any crash triggers loop
        assert!(detector.is_crash_loop(now));
    }

    #[test]
    fn record_crash_rollback_clears_detector() {
        let base = Utc::now();
        let mut detector = CrashLoopDetector::new(2, 300);
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        record.state = LifecycleState::Canary;

        detector.record_crash(base);
        let result = record.record_crash_and_maybe_rollback(
            &mut detector,
            base + chrono::Duration::seconds(1),
            "crash 2",
        );
        assert!(result.unwrap());
        assert_eq!(record.state, LifecycleState::RolledBack);

        // After rollback, detector should be cleared
        assert!(!detector.is_crash_loop(base + chrono::Duration::seconds(2)));
    }

    #[test]
    fn record_crash_rollback_from_production_succeeds() {
        let base = Utc::now();
        let mut detector = CrashLoopDetector::new(2, 300);
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        record.state = LifecycleState::Production;

        detector.record_crash(base);
        let result = record.record_crash_and_maybe_rollback(
            &mut detector,
            base + chrono::Duration::seconds(1),
            "production crash",
        );
        assert!(result.unwrap());
        assert_eq!(record.state, LifecycleState::RolledBack);
    }

    #[test]
    fn record_crash_rollback_from_pending_fails() {
        let base = Utc::now();
        let mut detector = CrashLoopDetector::new(2, 300);
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        // state is Pending (default)

        detector.record_crash(base);
        let result = record.record_crash_and_maybe_rollback(
            &mut detector,
            base + chrono::Duration::seconds(1),
            "pending crash",
        );
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canary Auto-Promotion / Rollback Decision Logic
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn auto_promote_requires_canary_state() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Production;
        record.health.success_rate = 100;
        record.health.samples = 1000;
        assert!(!record.should_auto_promote());
    }

    #[test]
    fn auto_promote_requires_min_samples() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Canary;
        record.canary_policy.min_samples = 100;
        record.health.success_rate = 100;
        record.health.samples = 50; // below minimum
        let far_future = Utc::now() + chrono::Duration::hours(2);
        assert!(!record.should_auto_promote_at(far_future));
    }

    #[test]
    fn auto_promote_requires_success_rate_above_threshold() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Canary;
        record.canary_policy.promotion_threshold = 95;
        record.canary_policy.min_samples = 10;
        record.canary_policy.min_canary_duration_secs = 0;
        record.health.success_rate = 90; // below 95
        record.health.samples = 100;
        assert!(!record.should_auto_promote());
    }

    #[test]
    fn auto_rollback_requires_canary_state() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Production;
        record.health.success_rate = 0;
        record.health.samples = 1000;
        assert!(!record.should_auto_rollback());
    }

    #[test]
    fn auto_rollback_requires_min_samples() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Canary;
        record.canary_policy.min_samples = 100;
        record.health.success_rate = 0;
        record.health.samples = 50; // below minimum
        assert!(!record.should_auto_rollback());
    }

    #[test]
    fn auto_rollback_triggers_when_below_threshold() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Canary;
        record.canary_policy.rollback_threshold = 80;
        record.canary_policy.min_samples = 10;
        record.health.success_rate = 70; // below 80
        record.health.samples = 100;
        assert!(record.should_auto_rollback());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleStatus Construction
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_status_from_record_basic() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert_eq!(status.state, LifecycleState::Pending);
        assert_eq!(status.version, test_version());
        assert!(!status.crash_loop_detected);
        assert!(!status.auto_promote_pending);
        assert!(!status.auto_rollback_pending);
        assert!(status.canary_expires_in_secs.is_none());
        assert!(status.rollback_target_version.is_none());
    }

    #[test]
    fn lifecycle_status_reflects_crash_loop_flag() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), true);
        assert!(status.crash_loop_detected);
        assert!(status.auto_rollback_pending); // crash loop sets rollback pending
    }

    #[test]
    fn lifecycle_status_with_rollback_target() {
        let record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert_eq!(
            status.rollback_target_version,
            Some(semver::Version::new(0, 9, 0))
        );
    }

    #[test]
    fn lifecycle_status_canary_expires_in_secs() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Canary;
        record.canary_policy.max_canary_duration_secs = 3600;
        let now = Utc::now();
        let status = LifecycleStatus::from_record(&record, now, false);
        assert!(status.canary_expires_in_secs.is_some());
    }

    #[test]
    fn lifecycle_status_not_in_canary_no_expiry() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Production;
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert!(status.canary_expires_in_secs.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transition Chain Integrity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn full_lifecycle_chain_pending_to_production_to_uninstalled() {
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
        record
            .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
            .unwrap();

        assert_eq!(record.state, LifecycleState::Uninstalled);
        assert_eq!(record.transitions.len(), 4);

        // Verify chain integrity: each transition.from matches previous transition.to
        for window in record.transitions.windows(2) {
            assert_eq!(
                window[0].to, window[1].from,
                "broken chain: {:?} -> {:?}",
                window[0], window[1]
            );
        }
    }

    #[test]
    fn rollback_and_retry_cycle() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());

        // Install and canary
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();

        // Rollback
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::AutoRollback {
                    health_score: 50,
                    failure_reason: "high error rate".into(),
                },
            )
            .unwrap();

        // Retry canary
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.0".into(),
                    to_version: "1.0.1".into(),
                },
            )
            .unwrap();

        // Succeed this time
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();

        assert_eq!(record.state, LifecycleState::Production);
        assert_eq!(record.transitions.len(), 5);
    }

    #[test]
    fn disable_and_re_enable_cycle() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Production;

        // Disable
        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "maintenance".into(),
                },
            )
            .unwrap();

        // Re-enable via canary
        record
            .transition(LifecycleState::Canary, TransitionReason::ManualPromotion)
            .unwrap();

        // Promote
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();

        assert_eq!(record.state, LifecycleState::Production);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleError Display + Equality
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_error_no_rollback_target_display_message() {
        let err = LifecycleError::NoRollbackTarget;
        let msg = err.to_string();
        assert!(msg.contains("rollback"), "expected rollback in: {msg}");
    }

    #[test]
    fn lifecycle_error_not_found_display_includes_id() {
        let err = LifecycleError::NotFound {
            connector_id: test_connector_id(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("test:lifecycle:v1"),
            "expected connector id in: {msg}"
        );
    }

    #[test]
    fn lifecycle_error_invalid_policy_display_includes_reason() {
        let err = LifecycleError::InvalidPolicy {
            reason: "bad config".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad config"), "expected reason in: {msg}");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleRecord Serde Roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_record_serde_roundtrip_with_health() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0))
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_promotion_threshold(90)
                    .with_rollback_threshold(70),
            );

        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        record.update_health(true, Some(42));

        let json = serde_json::to_string(&record).unwrap();
        let decoded: LifecycleRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.state, LifecycleState::Installing);
        assert_eq!(decoded.version, test_version());
        assert_eq!(decoded.transitions.len(), 1);
        assert_eq!(decoded.health.samples, 1);
        assert_eq!(
            decoded.previous_version,
            Some(semver::Version::new(0, 9, 0))
        );
    }

    #[test]
    fn lifecycle_status_serde_roundtrip_with_crash_loop() {
        let record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_previous_version(semver::Version::new(0, 9, 0));
        let status = LifecycleStatus::from_record(&record, Utc::now(), true);

        let json = serde_json::to_string(&status).unwrap();
        let decoded: LifecycleStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.state, LifecycleState::Pending);
        assert!(decoded.crash_loop_detected);
        assert_eq!(
            decoded.rollback_target_version,
            Some(semver::Version::new(0, 9, 0))
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State Machine: Multi-hop Transition Sequences
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn double_rollback_retry_cycle() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Installing;

        // First canary attempt
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::AutoRollback {
                    health_score: 40,
                    failure_reason: "first attempt".into(),
                },
            )
            .unwrap();

        // Second canary attempt
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.0".into(),
                    to_version: "1.0.1".into(),
                },
            )
            .unwrap();
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::ManualRollback {
                    reason: Some("second fail".into()),
                },
            )
            .unwrap();

        // Third canary -> success
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.1".into(),
                    to_version: "1.0.2".into(),
                },
            )
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::AutoPromotion { health_score: 99 },
            )
            .unwrap();

        assert_eq!(record.state, LifecycleState::Production);
        assert_eq!(record.transitions.len(), 6);
    }

    #[test]
    fn production_to_canary_to_disabled_to_canary_to_production() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::Production;

        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.0".into(),
                    to_version: "2.0.0".into(),
                },
            )
            .unwrap();
        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "emergency".into(),
                },
            )
            .unwrap();
        record
            .transition(LifecycleState::Canary, TransitionReason::ManualPromotion)
            .unwrap();
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .unwrap();

        assert_eq!(record.state, LifecycleState::Production);
        assert_eq!(record.transitions.len(), 4);
    }

    #[test]
    fn rolled_back_to_disabled_to_uninstalled() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.state = LifecycleState::RolledBack;

        record
            .transition(
                LifecycleState::Disabled,
                TransitionReason::Disabled {
                    reason: "no longer needed".into(),
                },
            )
            .unwrap();
        record
            .transition(LifecycleState::Uninstalled, TransitionReason::Uninstalled)
            .unwrap();

        assert_eq!(record.state, LifecycleState::Uninstalled);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HealthMetrics: Boundary Values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_metrics_large_sample_count() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        // Simulate high volume
        for _ in 0..1000 {
            record.update_health(true, Some(50));
        }
        assert_eq!(record.health.samples, 1000);
        assert_eq!(record.health.successes, 1000);
        assert_eq!(record.health.success_rate, 100);
        assert_eq!(record.health.total_latency_ms, 50_000);
    }

    #[test]
    fn health_metrics_mixed_latency_and_none() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(100));
        record.update_health(true, None);
        record.update_health(true, Some(300));
        record.update_health(true, None);

        assert_eq!(record.health.samples, 4);
        assert_eq!(record.health.latency_samples, 2);
        assert_eq!(record.health.total_latency_ms, 400);
        assert_eq!(record.health.avg_latency_ms(), Some(200));
    }

    #[test]
    fn health_metrics_max_latency_zero_remains_zero_without_samples() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, None);
        record.update_health(false, None);
        assert_eq!(record.health.max_latency_ms, 0);
    }

    #[test]
    fn health_metrics_max_latency_u32_max() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(u32::MAX));
        assert_eq!(record.health.max_latency_ms, u32::MAX);
    }

    #[test]
    fn health_metrics_avg_latency_large_total_clamps() {
        let m = HealthMetrics {
            total_latency_ms: u64::MAX,
            latency_samples: 1,
            ..Default::default()
        };
        // u64::MAX / 1 overflows u32 -> should return u32::MAX
        assert_eq!(m.avg_latency_ms(), Some(u32::MAX));
    }

    #[test]
    fn health_metrics_avg_latency_exact_division() {
        let m = HealthMetrics {
            total_latency_ms: 999,
            latency_samples: 3,
            ..Default::default()
        };
        assert_eq!(m.avg_latency_ms(), Some(333));
    }

    #[test]
    fn health_metrics_success_rate_near_boundary() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        // 1 success out of 2 = 50%
        record.update_health(true, None);
        record.update_health(false, None);
        assert_eq!(record.health.success_rate, 50);
    }

    #[test]
    fn health_metrics_success_rate_one_out_of_three() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, None);
        record.update_health(false, None);
        record.update_health(false, None);
        // 1/3 = 33.33% -> truncated to 33
        assert_eq!(record.health.success_rate, 33);
    }

    #[test]
    fn health_metrics_success_rate_two_out_of_three() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, None);
        record.update_health(true, None);
        record.update_health(false, None);
        // 2/3 = 66.67% -> rounded to 67 (clamped at 100 by update_health).
        assert_eq!(record.health.success_rate, 67);
    }

    #[test]
    fn health_reset_then_reaccumulate() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        for _ in 0..10 {
            record.update_health(true, Some(100));
        }
        record.reset_health();
        record.update_health(false, Some(200));
        assert_eq!(record.health.samples, 1);
        assert_eq!(record.health.failures, 1);
        assert_eq!(record.health.successes, 0);
        assert_eq!(record.health.success_rate, 0);
        assert_eq!(record.health.max_latency_ms, 200);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CanaryPolicy: Validation Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_policy_zero_promotion_one_rollback_invalid() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(0)
            .with_rollback_threshold(0);
        // 0 <= 0, so promotion_threshold is not greater => invalid
        assert!(policy.validate().is_err());
    }

    #[test]
    fn canary_policy_one_promotion_zero_rollback_valid() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(1)
            .with_rollback_threshold(0);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_max_u8_thresholds_valid() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(255)
            .with_rollback_threshold(254);
        // 255 > 254, traffic is default 10 <= 100
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_equal_durations_valid() {
        let policy = CanaryPolicy {
            min_canary_duration_secs: 600,
            max_canary_duration_secs: 600,
            ..CanaryPolicy::default()
        };
        // max >= min, so valid
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_zero_durations_valid() {
        let policy = CanaryPolicy {
            min_canary_duration_secs: 0,
            max_canary_duration_secs: 0,
            ..CanaryPolicy::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_max_u32_durations_valid() {
        let policy = CanaryPolicy {
            min_canary_duration_secs: 0,
            max_canary_duration_secs: u32::MAX,
            ..CanaryPolicy::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_zero_min_samples() {
        let policy = CanaryPolicy::new().with_min_samples(0);
        assert_eq!(policy.min_samples, 0);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn canary_policy_validate_error_message_thresholds() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(50)
            .with_rollback_threshold(60);
        let err = policy.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("promotion_threshold"));
        assert!(msg.contains("rollback_threshold"));
    }

    #[test]
    fn canary_policy_validate_error_message_traffic() {
        let policy = CanaryPolicy::new().with_canary_traffic_percent(200);
        let err = policy.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("canary_traffic_percent"));
    }

    #[test]
    fn canary_policy_validate_error_message_duration() {
        let policy = CanaryPolicy {
            min_canary_duration_secs: 7200,
            max_canary_duration_secs: 100,
            ..CanaryPolicy::default()
        };
        let err = policy.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("canary_duration"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleRecord Builder Patterns
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_record_builder_chaining() {
        let policy = CanaryPolicy::new()
            .with_promotion_threshold(98)
            .with_rollback_threshold(70)
            .with_min_samples(200)
            .with_min_canary_duration(120)
            .with_canary_traffic_percent(5);

        let record = LifecycleRecord::new(test_connector_id(), semver::Version::new(3, 2, 1))
            .with_canary_policy(policy)
            .with_previous_version(semver::Version::new(3, 2, 0));

        assert_eq!(record.version, semver::Version::new(3, 2, 1));
        assert_eq!(record.previous_version, Some(semver::Version::new(3, 2, 0)));
        assert_eq!(record.canary_policy.promotion_threshold, 98);
        assert_eq!(record.canary_policy.rollback_threshold, 70);
        assert_eq!(record.canary_policy.min_samples, 200);
        assert_eq!(record.canary_policy.min_canary_duration_secs, 120);
        assert_eq!(record.canary_policy.canary_traffic_percent, 5);
    }

    #[test]
    fn lifecycle_record_serde_without_optional_fields() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let json = serde_json::to_string(&record).unwrap();
        // previous_version should be skipped when None
        assert!(!json.contains("previous_version"));
        let decoded: LifecycleRecord = serde_json::from_str(&json).unwrap();
        assert!(decoded.previous_version.is_none());
    }

    #[test]
    fn lifecycle_record_serde_with_transitions() {
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

        let json = serde_json::to_string(&record).unwrap();
        let decoded: LifecycleRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.transitions.len(), 2);
        assert_eq!(decoded.transitions[0].from, LifecycleState::Pending);
        assert_eq!(decoded.transitions[0].to, LifecycleState::Installing);
        assert_eq!(decoded.transitions[1].from, LifecycleState::Installing);
        assert_eq!(decoded.transitions[1].to, LifecycleState::Canary);
    }

    #[test]
    fn lifecycle_record_clone_preserves_transitions() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();
        let cloned = record.clone();
        assert_eq!(record.transitions.len(), cloned.transitions.len());
        assert_eq!(record.state, cloned.state);
        assert_eq!(record.connector_id.as_str(), cloned.connector_id.as_str());
    }

    #[test]
    fn lifecycle_record_debug_output() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let debug = format!("{record:?}");
        assert!(debug.contains("LifecycleRecord"));
        assert!(debug.contains("Pending"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TransitionReason: Serde Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transition_reason_manual_rollback_none_serde() {
        let reason = TransitionReason::ManualRollback { reason: None };
        let json = serde_json::to_string(&reason).unwrap();
        let decoded: TransitionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, decoded);
        assert!(matches!(
            decoded,
            TransitionReason::ManualRollback { reason: None }
        ));
    }

    #[test]
    fn transition_reason_disabled_empty_reason_serde() {
        let reason = TransitionReason::Disabled {
            reason: String::new(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let decoded: TransitionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, decoded);
    }

    #[test]
    fn transition_reason_new_version_same_versions() {
        let reason = TransitionReason::NewVersion {
            from_version: "1.0.0".into(),
            to_version: "1.0.0".into(),
        };
        let display = reason.to_string();
        assert!(display.contains("1.0.0 -> 1.0.0"));
    }

    #[test]
    fn transition_reason_auto_rollback_boundary_health_scores() {
        let zero = TransitionReason::AutoRollback {
            health_score: 0,
            failure_reason: "total failure".into(),
        };
        assert!(zero.to_string().contains("0%"));

        let max = TransitionReason::AutoRollback {
            health_score: 255,
            failure_reason: "edge".into(),
        };
        assert!(max.to_string().contains("255%"));
    }

    #[test]
    fn transition_reason_auto_promotion_boundary_score() {
        let zero = TransitionReason::AutoPromotion { health_score: 0 };
        assert_eq!(zero.to_string(), "auto-promotion (health: 0%)");

        let max = TransitionReason::AutoPromotion { health_score: 255 };
        assert_eq!(max.to_string(), "auto-promotion (health: 255%)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleTransition: Builder and Fields
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_transition_with_initiator_empty_string() {
        let t = LifecycleTransition::new(
            LifecycleState::Canary,
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .with_initiator("");
        assert_eq!(t.initiated_by, Some(String::new()));
    }

    #[test]
    fn lifecycle_transition_timestamp_is_recent() {
        let before = Utc::now();
        let t = LifecycleTransition::new(
            LifecycleState::Pending,
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        );
        let after = Utc::now();
        assert!(t.timestamp >= before);
        assert!(t.timestamp <= after);
    }

    #[test]
    fn lifecycle_transition_debug_output() {
        let t = LifecycleTransition::new(
            LifecycleState::Canary,
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        );
        let debug = format!("{t:?}");
        assert!(debug.contains("LifecycleTransition"));
        assert!(debug.contains("Canary"));
        assert!(debug.contains("Production"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CrashLoopDetector: Advanced Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crash_loop_detector_very_large_window() {
        let mut detector = CrashLoopDetector::new(3, 1_000_000);
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        detector.record_crash(base - chrono::Duration::seconds(100_000));
        detector.record_crash(base - chrono::Duration::seconds(50_000));
        detector.record_crash(base);
        // All within the enormous window
        assert!(detector.is_crash_loop(base));
    }

    #[test]
    fn crash_loop_detector_crash_count_after_partial_prune() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut detector = CrashLoopDetector::new(5, 60);

        // Add 5 crashes: 3 old (outside window) + 2 recent
        detector.record_crash(base - chrono::Duration::seconds(100));
        detector.record_crash(base - chrono::Duration::seconds(90));
        detector.record_crash(base - chrono::Duration::seconds(80));
        detector.record_crash(base - chrono::Duration::seconds(30));
        detector.record_crash(base - chrono::Duration::seconds(10));

        assert_eq!(detector.crash_count_in_window(base), 2);
        assert!(!detector.is_crash_loop(base));
    }

    #[test]
    fn crash_loop_detector_success_then_rebuild() {
        let now = Utc::now();
        let mut detector = CrashLoopDetector::new(3, 60);

        // Build up crashes
        detector.record_crash(now);
        detector.record_crash(now);
        assert_eq!(detector.crash_count_in_window(now), 2);

        // Reset
        detector.record_success();
        assert_eq!(detector.crash_count_in_window(now), 0);

        // Rebuild
        detector.record_crash(now);
        assert_eq!(detector.crash_count_in_window(now), 1);
        assert!(!detector.is_crash_loop(now));
    }

    #[test]
    fn crash_loop_detector_serde_preserves_crashes() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut detector = CrashLoopDetector::new(3, 60);
        detector.record_crash(base - chrono::Duration::seconds(10));
        detector.record_crash(base);

        let json = serde_json::to_string(&detector).unwrap();
        let mut decoded: CrashLoopDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.crash_count_in_window(base), 2);
        assert_eq!(decoded.max_crashes, 3);
    }

    #[test]
    fn crash_loop_detector_debug_output() {
        let detector = CrashLoopDetector::new(5, 120);
        let debug = format!("{detector:?}");
        assert!(debug.contains("CrashLoopDetector"));
        assert!(debug.contains("max_crashes"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Auto-Promote/Rollback: Canary Start Timestamp Logic
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_start_uses_transition_timestamp_not_deployed_at() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(
                CanaryPolicy::new()
                    .with_min_canary_duration(60)
                    .with_promotion_threshold(90)
                    .with_min_samples(1),
            );
        // Deploy was long ago
        record.deployed_at = base - chrono::Duration::seconds(10_000);
        record.state = LifecycleState::Installing;

        // Transition to canary (this records a transition with current time)
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        record.update_health(true, Some(50));

        // The canary transition is ~now, so should_auto_promote should fail
        // because min_canary_duration=60 hasn't elapsed yet
        assert!(!record.should_auto_promote());
    }

    #[test]
    fn canary_start_uses_most_recent_canary_transition() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy {
                min_canary_duration_secs: 60,
                max_canary_duration_secs: 3600,
                promotion_threshold: 90,
                min_samples: 1,
                ..CanaryPolicy::default()
            });
        record.deployed_at = base - chrono::Duration::seconds(10_000);

        // First canary (old)
        record.state = LifecycleState::Installing;
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // Manually backdate the transition timestamp
        record.transitions.last_mut().unwrap().timestamp = base - chrono::Duration::seconds(500);

        // Rollback
        record
            .transition(
                LifecycleState::RolledBack,
                TransitionReason::ManualRollback { reason: None },
            )
            .unwrap();

        // Second canary (recent)
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.0.0".into(),
                    to_version: "1.0.1".into(),
                },
            )
            .unwrap();
        // Backdate second canary transition to 120 seconds ago
        record.transitions.last_mut().unwrap().timestamp = base - chrono::Duration::seconds(120);

        record.update_health(true, Some(50));

        // 120 seconds ago > min_canary_duration(60), so should promote
        assert!(record.should_auto_promote_at(base));
    }

    #[test]
    fn canary_expires_in_secs_uses_transition_not_deploy_time() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy {
                max_canary_duration_secs: 3600,
                ..CanaryPolicy::default()
            });

        // Deploy was 10 hours ago
        record.deployed_at = base - chrono::Duration::seconds(36_000);
        record.state = LifecycleState::Installing;
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        // Backdate canary transition to 60 seconds ago
        record.transitions.last_mut().unwrap().timestamp = base - chrono::Duration::seconds(60);

        let remaining = record.canary_expires_in_secs_at(base);
        assert_eq!(remaining, Some(3540)); // 3600 - 60 = 3540
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleError: Additional Coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_error_invalid_transition_eq() {
        let a = LifecycleError::InvalidTransition {
            from: LifecycleState::Pending,
            to: LifecycleState::Production,
        };
        let b = LifecycleError::InvalidTransition {
            from: LifecycleState::Pending,
            to: LifecycleState::Production,
        };
        assert_eq!(a, b);

        let c = LifecycleError::InvalidTransition {
            from: LifecycleState::Canary,
            to: LifecycleState::Production,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn lifecycle_error_invalid_policy_eq() {
        let a = LifecycleError::InvalidPolicy { reason: "x".into() };
        let b = LifecycleError::InvalidPolicy { reason: "x".into() };
        assert_eq!(a, b);

        let c = LifecycleError::InvalidPolicy { reason: "y".into() };
        assert_ne!(a, c);
    }

    #[test]
    fn lifecycle_error_not_found_eq() {
        let a = LifecycleError::NotFound {
            connector_id: test_connector_id(),
        };
        let b = LifecycleError::NotFound {
            connector_id: test_connector_id(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn lifecycle_error_persistence_eq() {
        let a = LifecycleError::Persistence {
            reason: "disk full".into(),
        };
        let b = LifecycleError::Persistence {
            reason: "disk full".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn lifecycle_error_debug_output() {
        let err = LifecycleError::InvalidTransition {
            from: LifecycleState::Canary,
            to: LifecycleState::Pending,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidTransition"));
        assert!(debug.contains("Canary"));
        assert!(debug.contains("Pending"));
    }

    #[test]
    fn lifecycle_error_source_is_none() {
        use std::error::Error;
        let err = LifecycleError::NoRollbackTarget;
        assert!(err.source().is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleStatus: Field Coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_status_connector_id_matches_record() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert_eq!(status.connector_id.as_str(), record.connector_id.as_str());
    }

    #[test]
    fn lifecycle_status_version_matches_record() {
        let record = LifecycleRecord::new(test_connector_id(), semver::Version::new(5, 6, 7));
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert_eq!(status.version, semver::Version::new(5, 6, 7));
    }

    #[test]
    fn lifecycle_status_health_reflects_record() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());
        record.update_health(true, Some(42));
        record.update_health(false, Some(99));
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        assert_eq!(status.health.samples, 2);
        assert_eq!(status.health.successes, 1);
        assert_eq!(status.health.failures, 1);
    }

    #[test]
    fn lifecycle_status_serde_skips_none_canary_expires() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("canary_expires_in_secs"));
    }

    #[test]
    fn lifecycle_status_serde_skips_none_rollback_target() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("rollback_target_version"));
    }

    #[test]
    fn lifecycle_status_debug_output() {
        let record = LifecycleRecord::new(test_connector_id(), test_version());
        let status = LifecycleStatus::from_record(&record, Utc::now(), false);
        let debug = format!("{status:?}");
        assert!(debug.contains("LifecycleStatus"));
        assert!(debug.contains("Pending"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleState: Display/as_str Consistency
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lifecycle_state_display_matches_as_str() {
        for state in ALL_STATES {
            assert_eq!(state.to_string(), state.as_str());
        }
    }

    #[test]
    fn lifecycle_state_all_variants_serde_json_values() {
        let expected = [
            ("\"pending\"", LifecycleState::Pending),
            ("\"installing\"", LifecycleState::Installing),
            ("\"canary\"", LifecycleState::Canary),
            ("\"production\"", LifecycleState::Production),
            ("\"rolled_back\"", LifecycleState::RolledBack),
            ("\"disabled\"", LifecycleState::Disabled),
            ("\"uninstalled\"", LifecycleState::Uninstalled),
        ];
        for (json, state) in expected {
            let serialized = serde_json::to_string(&state).unwrap();
            assert_eq!(serialized, json);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canary Expiry: Boundary Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_expires_in_secs_at_exactly_max_duration() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy {
                max_canary_duration_secs: 300,
                ..CanaryPolicy::default()
            });
        record.state = LifecycleState::Canary;
        record.deployed_at = base - chrono::Duration::seconds(300);
        record.transitions.clear();

        // Exactly at the boundary
        assert_eq!(record.canary_expires_in_secs_at(base), Some(0));
    }

    #[test]
    fn canary_expires_in_secs_at_one_second_before_max() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy {
                max_canary_duration_secs: 300,
                ..CanaryPolicy::default()
            });
        record.state = LifecycleState::Canary;
        record.deployed_at = base - chrono::Duration::seconds(299);
        record.transitions.clear();

        assert_eq!(record.canary_expires_in_secs_at(base), Some(1));
    }

    #[test]
    fn canary_expires_in_secs_with_future_deploy_time() {
        let base = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let mut record = LifecycleRecord::new(test_connector_id(), test_version())
            .with_canary_policy(CanaryPolicy {
                max_canary_duration_secs: 300,
                ..CanaryPolicy::default()
            });
        record.state = LifecycleState::Canary;
        // Deploy time in the future (clock skew scenario)
        record.deployed_at = base + chrono::Duration::seconds(60);
        record.transitions.clear();

        // Elapsed is negative, so should return max_canary_duration_secs
        assert_eq!(record.canary_expires_in_secs_at(base), Some(300));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LifecycleRecord: Transition with Initiator in Record
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transition_initiated_by_propagated_manually() {
        let mut record = LifecycleRecord::new(test_connector_id(), test_version());

        // transition() doesn't set initiated_by, but we can modify after
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .unwrap();

        // Verify the transition was stored without initiator
        assert!(record.transitions[0].initiated_by.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canary Policy: Serde Edge Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canary_policy_serde_all_fields_preserved() {
        let policy = CanaryPolicy {
            promotion_threshold: 99,
            rollback_threshold: 50,
            min_samples: 500,
            min_canary_duration_secs: 120,
            max_canary_duration_secs: 7200,
            canary_traffic_percent: 25,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: CanaryPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.promotion_threshold, 99);
        assert_eq!(decoded.rollback_threshold, 50);
        assert_eq!(decoded.min_samples, 500);
        assert_eq!(decoded.min_canary_duration_secs, 120);
        assert_eq!(decoded.max_canary_duration_secs, 7200);
        assert_eq!(decoded.canary_traffic_percent, 25);
    }

    #[test]
    fn canary_policy_debug_output() {
        let policy = CanaryPolicy::default();
        let debug = format!("{policy:?}");
        assert!(debug.contains("CanaryPolicy"));
        assert!(debug.contains("promotion_threshold"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Health Metrics: Debug and Clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_metrics_debug_output() {
        let m = HealthMetrics::default();
        let debug = format!("{m:?}");
        assert!(debug.contains("HealthMetrics"));
        assert!(debug.contains("successes"));
        assert!(debug.contains("success_rate"));
    }

    #[test]
    fn health_metrics_clone_preserves_all_fields() {
        let m = HealthMetrics {
            successes: 42,
            failures: 7,
            samples: 49,
            success_rate: 85,
            total_latency_ms: 9800,
            latency_samples: 49,
            max_latency_ms: 1000,
            last_updated: Utc::now(),
        };
        let cloned = m.clone();
        assert_eq!(m.successes, cloned.successes);
        assert_eq!(m.failures, cloned.failures);
        assert_eq!(m.samples, cloned.samples);
        assert_eq!(m.success_rate, cloned.success_rate);
        assert_eq!(m.total_latency_ms, cloned.total_latency_ms);
        assert_eq!(m.latency_samples, cloned.latency_samples);
        assert_eq!(m.max_latency_ms, cloned.max_latency_ms);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TransitionReason: Clone and Eq
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transition_reason_eq_all_variants() {
        let pairs: Vec<(TransitionReason, TransitionReason)> = vec![
            (
                TransitionReason::InstallComplete,
                TransitionReason::InstallComplete,
            ),
            (
                TransitionReason::ManualPromotion,
                TransitionReason::ManualPromotion,
            ),
            (TransitionReason::Uninstalled, TransitionReason::Uninstalled),
        ];
        for (a, b) in pairs {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn transition_reason_ne_different_variants() {
        assert_ne!(
            TransitionReason::InstallComplete,
            TransitionReason::ManualPromotion,
        );
        assert_ne!(
            TransitionReason::Uninstalled,
            TransitionReason::InstallComplete,
        );
    }

    #[test]
    fn transition_reason_clone_auto_rollback() {
        let r = TransitionReason::AutoRollback {
            health_score: 42,
            failure_reason: "network timeout".into(),
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn transition_reason_clone_new_version() {
        let r = TransitionReason::NewVersion {
            from_version: "1.0.0".into(),
            to_version: "2.0.0".into(),
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn transition_reason_debug_all_variants() {
        let variants: Vec<TransitionReason> = vec![
            TransitionReason::InstallComplete,
            TransitionReason::ManualPromotion,
            TransitionReason::AutoPromotion { health_score: 99 },
            TransitionReason::ManualRollback {
                reason: Some("test".into()),
            },
            TransitionReason::AutoRollback {
                health_score: 50,
                failure_reason: "err".into(),
            },
            TransitionReason::Disabled {
                reason: "maint".into(),
            },
            TransitionReason::Uninstalled,
            TransitionReason::NewVersion {
                from_version: "1.0.0".into(),
                to_version: "2.0.0".into(),
            },
        ];
        for v in variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C3.3: Type-state lifecycle acceptance tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn typed_lifecycle_full_happy_path() {
        // Pending -> Installing -> Canary -> Production
        let rec = TypedLifecycleRecord::new(test_connector_id(), test_version());
        assert_eq!(rec.state(), LifecycleState::Pending);

        let rec = rec.start_install(TransitionReason::InstallComplete);
        assert_eq!(rec.state(), LifecycleState::Installing);

        let rec = rec.start_canary(TransitionReason::ManualPromotion);
        assert_eq!(rec.state(), LifecycleState::Canary);

        let rec = rec.promote(TransitionReason::AutoPromotion { health_score: 99 });
        assert_eq!(rec.state(), LifecycleState::Production);

        // Audit trail preserved
        assert_eq!(rec.record().transitions.len(), 3);
    }

    #[test]
    fn typed_lifecycle_canary_rollback() {
        let rec = TypedLifecycleRecord::new(test_connector_id(), test_version())
            .start_install(TransitionReason::InstallComplete)
            .start_canary(TransitionReason::ManualPromotion)
            .rollback(TransitionReason::AutoRollback {
                health_score: 10,
                failure_reason: "high error rate".into(),
            });
        assert_eq!(rec.state(), LifecycleState::RolledBack);
        assert_eq!(rec.record().transitions.len(), 3);
    }

    #[test]
    fn typed_lifecycle_disable_from_production() {
        let rec = TypedLifecycleRecord::new(test_connector_id(), test_version())
            .start_install(TransitionReason::InstallComplete)
            .start_canary(TransitionReason::ManualPromotion)
            .promote(TransitionReason::AutoPromotion { health_score: 99 })
            .disable(TransitionReason::Disabled {
                reason: "maintenance".into(),
            });
        assert_eq!(rec.state(), LifecycleState::Disabled);
    }

    /// Invalid transitions are compile errors. This doc test demonstrates
    /// that `StatePending` has no `promote()` method.
    ///
    /// ```compile_fail
    /// use fcp_core::{TypedLifecycleRecord, ConnectorId, TransitionReason};
    /// let rec = TypedLifecycleRecord::new(
    ///     ConnectorId::from_static("test:fail:v1"),
    ///     semver::Version::new(1, 0, 0),
    /// );
    /// // ERROR: no method named `promote` found for `TypedLifecycleRecord<StatePending>`
    /// let _ = rec.promote(TransitionReason::AutoPromotion { health_score: 99 });
    /// ```
    #[test]
    fn typed_lifecycle_invalid_transition_is_compile_error() {
        // The actual compile failure is tested via the doc test above.
        // This test verifies the type system enforces state transitions.
        let pending = TypedLifecycleRecord::new(test_connector_id(), test_version());
        // pending.promote() would not compile
        // pending.rollback() would not compile
        // Only start_install() and uninstall() are available on StatePending
        let _ = pending.state(); // suppress unused
    }

    #[test]
    fn typed_lifecycle_erase_preserves_state() {
        let rec = TypedLifecycleRecord::new(test_connector_id(), test_version())
            .start_install(TransitionReason::InstallComplete)
            .start_canary(TransitionReason::ManualPromotion);
        let erased = rec.erase();
        assert_eq!(erased.state(), LifecycleState::Canary);
        assert_eq!(erased.record().transitions.len(), 2);
    }

    #[test]
    fn typed_lifecycle_serde_via_erased() {
        let rec = TypedLifecycleRecord::new(test_connector_id(), test_version())
            .start_install(TransitionReason::InstallComplete);
        let erased = rec.erase();
        let json = serde_json::to_string(&erased).unwrap();
        let back: AnyLifecycleRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state(), LifecycleState::Installing);
        assert_eq!(back.record().connector_id, test_connector_id());
    }

    #[test]
    fn any_lifecycle_from_runtime_record() {
        let runtime = LifecycleRecord::new(test_connector_id(), test_version());
        let any = AnyLifecycleRecord::from_record(runtime);
        assert_eq!(any.state(), LifecycleState::Pending);
    }

    #[test]
    fn typed_lifecycle_uninstalled_is_terminal() {
        let rec = TypedLifecycleRecord::new(test_connector_id(), test_version())
            .uninstall(TransitionReason::Uninstalled);
        assert_eq!(rec.state(), LifecycleState::Uninstalled);
        // No transition methods available on StateUninstalled — verified by type system
        let erased = rec.erase();
        assert_eq!(erased.state(), LifecycleState::Uninstalled);
    }
}
