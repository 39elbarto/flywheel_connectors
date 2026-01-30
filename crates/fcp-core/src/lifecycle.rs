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
        matches!(self, Self::Pending | Self::Installing | Self::RolledBack)
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
        self.state == LifecycleState::Canary
            && self.health.success_rate >= self.canary_policy.promotion_threshold
            && self.health.samples >= self.canary_policy.min_samples
            && self.canary_duration_exceeded()
    }

    /// Check if the connector should be auto-rolled-back based on health.
    #[must_use]
    pub fn should_auto_rollback(&self) -> bool {
        self.state == LifecycleState::Canary
            && self.health.success_rate < self.canary_policy.rollback_threshold
            && self.health.samples >= self.canary_policy.min_samples
    }

    /// Check if the minimum canary duration has passed.
    fn canary_duration_exceeded(&self) -> bool {
        let canary_start = self
            .transitions
            .iter()
            .rev()
            .find(|t| t.to == LifecycleState::Canary)
            .map_or(self.deployed_at, |t| t.timestamp);

        let duration = Utc::now().signed_duration_since(canary_start);
        duration.num_seconds() >= i64::from(self.canary_policy.min_canary_duration_secs)
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

        // Update success rate (safe: result is 0-100)
        if self.health.samples > 0 {
            self.health.success_rate =
                (self.health.successes as f64 / self.health.samples as f64 * 100.0) as u8;
        }

        // Update latency tracking
        if let Some(latency) = latency_ms {
            self.health.total_latency_ms += u64::from(latency);
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
            .checked_div(self.samples)
            .map(|avg| avg as u32)
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
        assert!(LifecycleState::Pending.can_start_canary());
        assert!(LifecycleState::Installing.can_start_canary());
        assert!(LifecycleState::RolledBack.can_start_canary());
        assert!(!LifecycleState::Canary.can_start_canary());
        assert!(!LifecycleState::Production.can_start_canary());
        assert!(!LifecycleState::Disabled.can_start_canary());
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
}
