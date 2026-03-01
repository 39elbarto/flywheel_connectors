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

    fn test_key() -> CapabilityUsageKey {
        CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.example:request-response:1"),
            CapabilityId::from_static("fcp.example.read"),
        )
    }

    fn test_event(outcome: CapabilityUsageOutcome) -> CapabilityUsageEvent {
        CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:alice").expect("principal id"),
            SafetyTier::Risky,
            OperationId::from_static("op.list"),
            outcome,
            1_738_387_200,
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn constants_are_namespaced() {
        assert!(CAPABILITY_USAGE_FORMAT.starts_with("fcp-"));
        assert_eq!(CAPABILITY_USAGE_SCHEMA_VERSION, "1.0");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageOutcome
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn outcome_serde_all_variants() {
        let variants = [
            (CapabilityUsageOutcome::Allow, "\"allow\""),
            (CapabilityUsageOutcome::Deny, "\"deny\""),
            (CapabilityUsageOutcome::Error, "\"error\""),
        ];
        for (outcome, expected) in &variants {
            let json = serde_json::to_string(outcome).unwrap();
            assert_eq!(&json, expected, "serialization mismatch for {outcome:?}");
            let decoded: CapabilityUsageOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*outcome, decoded);
        }
    }

    #[test]
    fn outcome_copy() {
        let a = CapabilityUsageOutcome::Allow;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn outcome_clone() {
        let a = CapabilityUsageOutcome::Deny;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageKey
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_new_fields() {
        let key = test_key();
        assert_eq!(key.zone_id, ZoneId::work());
        assert_eq!(key.connector_id.as_str(), "fcp.example:request-response:1");
        assert_eq!(key.capability_id.as_str(), "fcp.example.read");
    }

    #[test]
    fn key_equality() {
        let a = test_key();
        let b = test_key();
        assert_eq!(a, b);
    }

    #[test]
    fn key_inequality() {
        let a = test_key();
        let b = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.other:streaming:1"),
            CapabilityId::from_static("fcp.example.read"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn key_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(test_key());
        set.insert(test_key());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn key_hash_different_keys() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(test_key());
        set.insert(CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.other:streaming:1"),
            CapabilityId::from_static("fcp.other.write"),
        ));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn key_serde_roundtrip() {
        let key = test_key();
        let json = serde_json::to_string(&key).unwrap();
        let decoded: CapabilityUsageKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn key_clone() {
        let key = test_key();
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageEvent
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_usage_event_new_sets_format_and_version() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert_eq!(event.format, CAPABILITY_USAGE_FORMAT);
        assert_eq!(event.schema_version, CAPABILITY_USAGE_SCHEMA_VERSION);
    }

    #[test]
    fn event_new_fields() {
        let event = test_event(CapabilityUsageOutcome::Deny);
        assert_eq!(event.zone_id, ZoneId::work());
        assert_eq!(
            event.connector_id.as_str(),
            "fcp.example:request-response:1"
        );
        assert_eq!(event.capability_id.as_str(), "fcp.example.read");
        assert_eq!(event.principal_id.as_str(), "user:alice");
        assert_eq!(event.risk_tier, SafetyTier::Risky);
        assert_eq!(event.operation.as_str(), "op.list");
        assert_eq!(event.outcome, CapabilityUsageOutcome::Deny);
        assert_eq!(event.occurred_at, 1_738_387_200);
    }

    #[test]
    fn event_key_extracts_aggregation_key() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let key = event.key();
        assert_eq!(key.zone_id, event.zone_id);
        assert_eq!(key.connector_id, event.connector_id);
        assert_eq!(key.capability_id, event.capability_id);
    }

    #[test]
    fn event_key_roundtrip_matches() {
        let original_key = test_key();
        let event = test_event(CapabilityUsageOutcome::Error);
        let extracted_key = event.key();
        assert_eq!(original_key, extracted_key);
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CapabilityUsageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.format, event.format);
        assert_eq!(decoded.schema_version, event.schema_version);
        assert_eq!(decoded.zone_id, event.zone_id);
        assert_eq!(decoded.connector_id, event.connector_id);
        assert_eq!(decoded.outcome, event.outcome);
        assert_eq!(decoded.occurred_at, event.occurred_at);
    }

    #[test]
    fn event_clone() {
        let event = test_event(CapabilityUsageOutcome::Deny);
        let cloned = event.clone();
        assert_eq!(cloned.format, event.format);
        assert_eq!(cloned.outcome, event.outcome);
        assert_eq!(cloned.occurred_at, event.occurred_at);
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

    #[test]
    fn event_deserialize_with_explicit_format() {
        let raw = r#"{
            "format": "fcp-capability-usage",
            "schema_version": "1.0",
            "zone_id": "z:work",
            "connector_id": "fcp.example:request-response:1",
            "capability_id": "fcp.example.read",
            "principal_id": "user:alice",
            "risk_tier": "safe",
            "operation": "op.read",
            "outcome": "deny",
            "occurred_at": 100
        }"#;
        let event: CapabilityUsageEvent = serde_json::from_str(raw).unwrap();
        assert_eq!(event.outcome, CapabilityUsageOutcome::Deny);
        assert_eq!(event.risk_tier, SafetyTier::Safe);
    }

    #[test]
    fn event_all_outcome_variants() {
        for outcome in [
            CapabilityUsageOutcome::Allow,
            CapabilityUsageOutcome::Deny,
            CapabilityUsageOutcome::Error,
        ] {
            let event = test_event(outcome);
            let json = serde_json::to_string(&event).unwrap();
            let decoded: CapabilityUsageEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.outcome, outcome);
        }
    }

    #[test]
    fn event_different_risk_tiers() {
        for tier in [SafetyTier::Safe, SafetyTier::Risky, SafetyTier::Dangerous] {
            let event = CapabilityUsageEvent::new(
                test_key(),
                PrincipalId::new("user:bob").expect("principal id"),
                tier,
                OperationId::from_static("op.write"),
                CapabilityUsageOutcome::Allow,
                999,
            );
            let json = serde_json::to_string(&event).unwrap();
            let decoded: CapabilityUsageEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.risk_tier, tier);
        }
    }

    #[test]
    fn event_json_contains_expected_fields() {
        let event = test_event(CapabilityUsageOutcome::Error);
        let value = serde_json::to_value(&event).unwrap();
        assert!(value.get("format").is_some());
        assert!(value.get("schema_version").is_some());
        assert!(value.get("zone_id").is_some());
        assert!(value.get("connector_id").is_some());
        assert!(value.get("capability_id").is_some());
        assert!(value.get("principal_id").is_some());
        assert!(value.get("risk_tier").is_some());
        assert!(value.get("operation").is_some());
        assert!(value.get("outcome").is_some());
        assert!(value.get("occurred_at").is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageOutcome – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn outcome_debug_format() {
        assert_eq!(format!("{:?}", CapabilityUsageOutcome::Allow), "Allow");
        assert_eq!(format!("{:?}", CapabilityUsageOutcome::Deny), "Deny");
        assert_eq!(format!("{:?}", CapabilityUsageOutcome::Error), "Error");
    }

    #[test]
    fn outcome_equality() {
        assert_eq!(CapabilityUsageOutcome::Allow, CapabilityUsageOutcome::Allow);
        assert_ne!(CapabilityUsageOutcome::Allow, CapabilityUsageOutcome::Deny);
        assert_ne!(CapabilityUsageOutcome::Deny, CapabilityUsageOutcome::Error);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageKey – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_debug_format() {
        let key = test_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("CapabilityUsageKey"));
        assert!(debug.contains("fcp.example"));
    }

    #[test]
    fn key_zone_sensitivity() {
        let a = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.a:rr:1"),
            CapabilityId::from_static("fcp.a.read"),
        );
        let b = CapabilityUsageKey::new(
            ZoneId::private(),
            ConnectorId::from_static("fcp.a:rr:1"),
            CapabilityId::from_static("fcp.a.read"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn key_connector_sensitivity() {
        let a = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.a:rr:1"),
            CapabilityId::from_static("fcp.a.read"),
        );
        let b = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.b:rr:1"),
            CapabilityId::from_static("fcp.a.read"),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn key_capability_sensitivity() {
        let a = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.a:rr:1"),
            CapabilityId::from_static("fcp.a.read"),
        );
        let b = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.a:rr:1"),
            CapabilityId::from_static("fcp.a.write"),
        );
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageEvent – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_occurred_at_zero() {
        let event = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:zero").expect("principal id"),
            SafetyTier::Safe,
            OperationId::from_static("op.noop"),
            CapabilityUsageOutcome::Allow,
            0,
        );
        assert_eq!(event.occurred_at, 0);
    }

    #[test]
    fn event_occurred_at_max() {
        let event = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:max").expect("principal id"),
            SafetyTier::Dangerous,
            OperationId::from_static("op.big"),
            CapabilityUsageOutcome::Error,
            u64::MAX,
        );
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CapabilityUsageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.occurred_at, u64::MAX);
    }

    #[test]
    fn event_debug_format() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let debug = format!("{event:?}");
        assert!(debug.contains("CapabilityUsageEvent"));
        assert!(debug.contains("fcp-capability-usage"));
    }

    #[test]
    fn event_clone_preserves_all_fields() {
        let event = test_event(CapabilityUsageOutcome::Deny);
        let cloned = Clone::clone(&event);
        assert_eq!(cloned.format, event.format);
        assert_eq!(cloned.schema_version, event.schema_version);
        assert_eq!(cloned.zone_id, event.zone_id);
        assert_eq!(cloned.connector_id, event.connector_id);
        assert_eq!(cloned.capability_id, event.capability_id);
        assert_eq!(cloned.principal_id, event.principal_id);
        assert_eq!(cloned.risk_tier, event.risk_tier);
        assert_eq!(cloned.operation, event.operation);
        assert_eq!(cloned.outcome, event.outcome);
        assert_eq!(cloned.occurred_at, event.occurred_at);
    }

    #[test]
    fn event_different_principals_produce_different_events() {
        let e1 = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:alice").expect("principal id"),
            SafetyTier::Safe,
            OperationId::from_static("op.read"),
            CapabilityUsageOutcome::Allow,
            1000,
        );
        let e2 = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:bob").expect("principal id"),
            SafetyTier::Safe,
            OperationId::from_static("op.read"),
            CapabilityUsageOutcome::Allow,
            1000,
        );
        // Same key, different principals
        assert_eq!(e1.key(), e2.key());
        assert_ne!(e1.principal_id, e2.principal_id);
    }

    #[test]
    fn key_clone_is_equal() {
        let key = test_key();
        let cloned = Clone::clone(&key);
        assert_eq!(key, cloned);
        assert_eq!(key.zone_id, cloned.zone_id);
        assert_eq!(key.connector_id, cloned.connector_id);
        assert_eq!(key.capability_id, cloned.capability_id);
    }

    #[test]
    fn event_format_is_constant() {
        let e1 = test_event(CapabilityUsageOutcome::Allow);
        let e2 = test_event(CapabilityUsageOutcome::Error);
        assert_eq!(e1.format, e2.format);
        assert_eq!(e1.schema_version, e2.schema_version);
    }

    #[test]
    fn event_key_is_independent_of_outcome_and_principal() {
        let key = test_key();
        for outcome in [
            CapabilityUsageOutcome::Allow,
            CapabilityUsageOutcome::Deny,
            CapabilityUsageOutcome::Error,
        ] {
            let event = test_event(outcome);
            assert_eq!(event.key(), key);
        }
    }
}
