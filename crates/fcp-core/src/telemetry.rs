//! Capability usage telemetry types (NORMATIVE).
//!
//! Provides structured events for capability usage aggregation and
//! least-privilege analysis.

use serde::{Deserialize, Serialize};

use crate::{CapabilityId, ConnectorId, OperationId, PrincipalId, SafetyTier, ZoneId};

/// Usage outcome for a capability invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityUsageOutcome {
    /// Capability invocation was allowed.
    Allow,
    /// Capability invocation was denied.
    Deny,
    /// Capability invocation failed with an error.
    Error,
}

/// Aggregation key for capability usage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityUsageKey {
    pub zone_id: ZoneId,
    pub connector_id: ConnectorId,
    pub capability_id: CapabilityId,
}

impl CapabilityUsageKey {
    /// Build a new usage key.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        capability_id: CapabilityId,
    ) -> Self {
        Self {
            zone_id,
            connector_id,
            capability_id,
        }
    }
}

/// Capability usage event for telemetry aggregation (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUsageEvent {
    /// Zone where the capability was invoked.
    pub zone_id: ZoneId,
    /// Connector that executed the operation.
    pub connector_id: ConnectorId,
    /// Capability identifier used for the operation.
    pub capability_id: CapabilityId,
    /// Principal who initiated the request.
    pub principal_id: PrincipalId,
    /// Safety tier associated with the operation.
    pub risk_tier: SafetyTier,
    /// Operation identifier (connector-defined).
    pub operation: OperationId,
    /// Outcome for the invocation.
    pub outcome: CapabilityUsageOutcome,
    /// When the usage occurred (Unix timestamp seconds).
    pub occurred_at: u64,
}

impl CapabilityUsageEvent {
    /// Create a new capability usage event.
    #[must_use]
    pub fn new(
        key: CapabilityUsageKey,
        principal_id: PrincipalId,
        risk_tier: SafetyTier,
        operation: OperationId,
        outcome: CapabilityUsageOutcome,
        occurred_at: u64,
    ) -> Self {
        let CapabilityUsageKey {
            zone_id,
            connector_id,
            capability_id,
        } = key;
        Self {
            zone_id,
            connector_id,
            capability_id,
            principal_id,
            risk_tier,
            operation,
            outcome,
            occurred_at,
        }
    }

    /// Compute the aggregation key for this event.
    #[must_use]
    pub fn key(&self) -> CapabilityUsageKey {
        CapabilityUsageKey::new(
            self.zone_id.clone(),
            self.connector_id.clone(),
            self.capability_id.clone(),
        )
    }
}
