//! Capability usage telemetry types (NORMATIVE).
//!
//! Provides structured events for capability usage aggregation and
//! least-privilege analysis.

use serde::{Deserialize, Serialize};

use crate::{CapabilityId, ConnectorId, OperationId, PrincipalId, SafetyTier, ZoneId};

/// Capability usage format identifier.
pub const CAPABILITY_USAGE_FORMAT: &str = "fcp-capability-usage";

/// Capability usage schema version.
pub const CAPABILITY_USAGE_SCHEMA_VERSION: &str = "1.0";

fn capability_usage_format() -> String {
    CAPABILITY_USAGE_FORMAT.to_string()
}

fn capability_usage_schema_version() -> String {
    CAPABILITY_USAGE_SCHEMA_VERSION.to_string()
}

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
    /// Format identifier (always "fcp-capability-usage").
    #[serde(default = "capability_usage_format")]
    pub format: String,
    /// Schema version (always "1.0").
    #[serde(default = "capability_usage_schema_version")]
    pub schema_version: String,
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
            format: capability_usage_format(),
            schema_version: capability_usage_schema_version(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_usage_event_new_sets_format_and_version() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.example:request-response:1"),
            CapabilityId::from_static("fcp.example.read"),
        );
        let event = CapabilityUsageEvent::new(
            key,
            PrincipalId::new("user:alice").expect("principal id"),
            SafetyTier::Risky,
            OperationId::from_static("op.list"),
            CapabilityUsageOutcome::Allow,
            42,
        );

        assert_eq!(event.format, CAPABILITY_USAGE_FORMAT);
        assert_eq!(event.schema_version, CAPABILITY_USAGE_SCHEMA_VERSION);
    }

    #[test]
    fn capability_usage_event_deserialize_defaults_format_and_version() {
        let raw = r#"{
            "zone_id": "z:work",
            "connector_id": "fcp.example:request-response:1",
            "capability_id": "fcp.example.read",
            "principal_id": "user:alice",
            "risk_tier": "risky",
            "operation": "op.list",
            "outcome": "allow",
            "occurred_at": 1738387200
        }"#;
        let event: CapabilityUsageEvent =
            serde_json::from_str(raw).expect("capability usage event");

        assert_eq!(event.format, CAPABILITY_USAGE_FORMAT);
        assert_eq!(event.schema_version, CAPABILITY_USAGE_SCHEMA_VERSION);
    }
}
