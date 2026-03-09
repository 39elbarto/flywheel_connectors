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

    // ─────────────────────────────────────────────────────────────────────────
    // Constants – additional
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn constant_format_value() {
        assert_eq!(CAPABILITY_USAGE_FORMAT, "fcp-capability-usage");
    }

    #[test]
    fn constant_schema_version_value() {
        assert_eq!(CAPABILITY_USAGE_SCHEMA_VERSION, "1.0");
    }

    #[test]
    fn capability_usage_format_fn_returns_owned() {
        let s = capability_usage_format();
        assert_eq!(s, CAPABILITY_USAGE_FORMAT);
        assert_eq!(s.len(), CAPABILITY_USAGE_FORMAT.len());
    }

    #[test]
    fn capability_usage_schema_version_fn_returns_owned() {
        let s = capability_usage_schema_version();
        assert_eq!(s, CAPABILITY_USAGE_SCHEMA_VERSION);
    }

    #[test]
    fn format_constant_contains_fcp_prefix() {
        assert!(CAPABILITY_USAGE_FORMAT.starts_with("fcp-"));
    }

    #[test]
    fn schema_version_is_semver_like() {
        let parts: Vec<&str> = CAPABILITY_USAGE_SCHEMA_VERSION.split('.').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<u32>().is_ok());
        assert!(parts[1].parse::<u32>().is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageOutcome – additional
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn outcome_allow_serde_roundtrip() {
        let json = serde_json::to_string(&CapabilityUsageOutcome::Allow).unwrap();
        assert_eq!(json, "\"allow\"");
        let decoded: CapabilityUsageOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, CapabilityUsageOutcome::Allow);
    }

    #[test]
    fn outcome_deny_serde_roundtrip() {
        let json = serde_json::to_string(&CapabilityUsageOutcome::Deny).unwrap();
        assert_eq!(json, "\"deny\"");
        let decoded: CapabilityUsageOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, CapabilityUsageOutcome::Deny);
    }

    #[test]
    fn outcome_error_serde_roundtrip() {
        let json = serde_json::to_string(&CapabilityUsageOutcome::Error).unwrap();
        assert_eq!(json, "\"error\"");
        let decoded: CapabilityUsageOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, CapabilityUsageOutcome::Error);
    }

    #[test]
    fn outcome_rejects_unknown_variant() {
        let result = serde_json::from_str::<CapabilityUsageOutcome>("\"unknown\"");
        assert!(result.is_err());
    }

    #[test]
    fn outcome_rejects_capitalized() {
        let result = serde_json::from_str::<CapabilityUsageOutcome>("\"Allow\"");
        assert!(result.is_err());
    }

    #[test]
    fn outcome_rejects_numeric() {
        let result = serde_json::from_str::<CapabilityUsageOutcome>("42");
        assert!(result.is_err());
    }

    #[test]
    fn outcome_rejects_null() {
        let result = serde_json::from_str::<CapabilityUsageOutcome>("null");
        assert!(result.is_err());
    }

    #[test]
    fn outcome_rejects_empty_string() {
        let result = serde_json::from_str::<CapabilityUsageOutcome>("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn outcome_copy_semantics() {
        let a = CapabilityUsageOutcome::Error;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, CapabilityUsageOutcome::Error);
    }

    #[test]
    fn outcome_ne_all_pairs() {
        let variants = [
            CapabilityUsageOutcome::Allow,
            CapabilityUsageOutcome::Deny,
            CapabilityUsageOutcome::Error,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn outcome_debug_deny() {
        assert_eq!(format!("{:?}", CapabilityUsageOutcome::Deny), "Deny");
    }

    #[test]
    fn outcome_debug_error() {
        assert_eq!(format!("{:?}", CapabilityUsageOutcome::Error), "Error");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageKey – additional
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_serde_json_value_has_all_fields() {
        let key = test_key();
        let value = serde_json::to_value(&key).unwrap();
        assert!(value.get("zone_id").is_some());
        assert!(value.get("connector_id").is_some());
        assert!(value.get("capability_id").is_some());
    }

    #[test]
    fn key_serde_json_value_field_count() {
        let key = test_key();
        let value = serde_json::to_value(&key).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn key_hash_map_usage() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let key = test_key();
        map.insert(key.clone(), 42u64);
        assert_eq!(map[&key], 42);
    }

    #[test]
    fn key_hash_map_overwrite() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let key = test_key();
        map.insert(key.clone(), 1);
        map.insert(key.clone(), 2);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&key], 2);
    }

    #[test]
    fn key_different_zone_ids() {
        let k1 = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("c:rr:1"),
            CapabilityId::from_static("cap.x"),
        );
        let k2 = CapabilityUsageKey::new(
            ZoneId::private(),
            ConnectorId::from_static("c:rr:1"),
            CapabilityId::from_static("cap.x"),
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_different_connectors_same_cap() {
        let k1 = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("a:rr:1"),
            CapabilityId::from_static("cap.r"),
        );
        let k2 = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("b:rr:1"),
            CapabilityId::from_static("cap.r"),
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_different_capabilities_same_connector() {
        let k1 = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("c:rr:1"),
            CapabilityId::from_static("cap.read"),
        );
        let k2 = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("c:rr:1"),
            CapabilityId::from_static("cap.write"),
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_debug_contains_all_ids() {
        let key = test_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("zone_id"));
        assert!(debug.contains("connector_id"));
        assert!(debug.contains("capability_id"));
    }

    #[test]
    fn key_clone_independence() {
        let key = test_key();
        let cloned = key.clone();
        // After clone, original still accessible
        assert_eq!(key.zone_id, cloned.zone_id);
        assert_eq!(key.connector_id, cloned.connector_id);
        assert_eq!(key.capability_id, cloned.capability_id);
    }

    #[test]
    fn key_deserialize_from_raw_json() {
        let raw = r#"{
            "zone_id": "z:work",
            "connector_id": "fcp.test:rr:1",
            "capability_id": "fcp.test.read"
        }"#;
        let key: CapabilityUsageKey = serde_json::from_str(raw).unwrap();
        assert_eq!(key.zone_id, ZoneId::work());
        assert_eq!(key.connector_id.as_str(), "fcp.test:rr:1");
        assert_eq!(key.capability_id.as_str(), "fcp.test.read");
    }

    #[test]
    fn key_deserialize_missing_field_fails() {
        let raw = r#"{
            "zone_id": "z:work",
            "connector_id": "fcp.test:rr:1"
        }"#;
        let result = serde_json::from_str::<CapabilityUsageKey>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn key_eq_reflexive() {
        let key = test_key();
        assert_eq!(key, key.clone());
    }

    #[test]
    fn key_eq_symmetric() {
        let a = test_key();
        let b = test_key();
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityUsageEvent – additional
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_format_field_value() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert_eq!(event.format, "fcp-capability-usage");
    }

    #[test]
    fn event_schema_version_field_value() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert_eq!(event.schema_version, "1.0");
    }

    #[test]
    fn event_principal_id_preserved() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert_eq!(event.principal_id.as_str(), "user:alice");
    }

    #[test]
    fn event_operation_preserved() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert_eq!(event.operation.as_str(), "op.list");
    }

    #[test]
    fn event_different_operations() {
        let ops = ["op.read", "op.write", "op.delete", "op.list"];
        for op in ops {
            let event = CapabilityUsageEvent::new(
                test_key(),
                PrincipalId::new("user:x").expect("principal"),
                SafetyTier::Safe,
                OperationId::from_static(op),
                CapabilityUsageOutcome::Allow,
                100,
            );
            assert_eq!(event.operation.as_str(), op);
        }
    }

    #[test]
    fn event_serde_json_field_names() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"format\""));
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"zone_id\""));
        assert!(json.contains("\"connector_id\""));
        assert!(json.contains("\"capability_id\""));
        assert!(json.contains("\"principal_id\""));
        assert!(json.contains("\"risk_tier\""));
        assert!(json.contains("\"operation\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"occurred_at\""));
    }

    #[test]
    fn event_serde_outcome_allow_in_json() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"allow\""));
    }

    #[test]
    fn event_serde_outcome_deny_in_json() {
        let event = test_event(CapabilityUsageOutcome::Deny);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"deny\""));
    }

    #[test]
    fn event_serde_outcome_error_in_json() {
        let event = test_event(CapabilityUsageOutcome::Error);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"error\""));
    }

    #[test]
    fn event_deserialize_missing_format_uses_default() {
        let raw = r#"{
            "zone_id": "z:work",
            "connector_id": "fcp.x:rr:1",
            "capability_id": "fcp.x.read",
            "principal_id": "user:test",
            "risk_tier": "safe",
            "operation": "op.a",
            "outcome": "allow",
            "occurred_at": 50
        }"#;
        let event: CapabilityUsageEvent = serde_json::from_str(raw).unwrap();
        assert_eq!(event.format, CAPABILITY_USAGE_FORMAT);
        assert_eq!(event.schema_version, CAPABILITY_USAGE_SCHEMA_VERSION);
    }

    #[test]
    fn event_deserialize_missing_required_field_fails() {
        let raw = r#"{
            "format": "fcp-capability-usage",
            "schema_version": "1.0",
            "zone_id": "z:work"
        }"#;
        let result = serde_json::from_str::<CapabilityUsageEvent>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn event_multiple_events_same_key() {
        let events: Vec<CapabilityUsageEvent> = (0..5)
            .map(|i| {
                CapabilityUsageEvent::new(
                    test_key(),
                    PrincipalId::new("user:alice").expect("principal"),
                    SafetyTier::Safe,
                    OperationId::from_static("op.list"),
                    CapabilityUsageOutcome::Allow,
                    i * 100,
                )
            })
            .collect();
        let keys: Vec<CapabilityUsageKey> = events.iter().map(CapabilityUsageEvent::key).collect();
        for k in &keys {
            assert_eq!(k, &keys[0]);
        }
    }

    #[test]
    fn event_different_keys_are_distinct() {
        let e1 = test_event(CapabilityUsageOutcome::Allow);
        let e2 = CapabilityUsageEvent::new(
            CapabilityUsageKey::new(
                ZoneId::private(),
                ConnectorId::from_static("fcp.other:rr:1"),
                CapabilityId::from_static("fcp.other.write"),
            ),
            PrincipalId::new("user:bob").expect("principal"),
            SafetyTier::Dangerous,
            OperationId::from_static("op.delete"),
            CapabilityUsageOutcome::Deny,
            9999,
        );
        assert_ne!(e1.key(), e2.key());
    }

    #[test]
    fn event_clone_debug_matches() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let cloned = event.clone();
        let d1 = format!("{event:?}");
        let d2 = format!("{cloned:?}");
        assert_eq!(d1, d2);
    }

    #[test]
    fn event_safe_tier_serde() {
        let event = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:s").expect("principal"),
            SafetyTier::Safe,
            OperationId::from_static("op.safe"),
            CapabilityUsageOutcome::Allow,
            1,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"safe\""));
    }

    #[test]
    fn event_dangerous_tier_serde() {
        let event = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:d").expect("principal"),
            SafetyTier::Dangerous,
            OperationId::from_static("op.danger"),
            CapabilityUsageOutcome::Deny,
            2,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"dangerous\""));
    }

    #[test]
    fn event_risky_tier_serde() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"risky\""));
    }

    #[test]
    fn event_occurred_at_one() {
        let event = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:t").expect("principal"),
            SafetyTier::Safe,
            OperationId::from_static("op.t"),
            CapabilityUsageOutcome::Allow,
            1,
        );
        assert_eq!(event.occurred_at, 1);
    }

    #[test]
    fn event_occurred_at_large_value() {
        let ts = 4_102_444_800; // year 2100
        let event = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:future").expect("principal"),
            SafetyTier::Safe,
            OperationId::from_static("op.f"),
            CapabilityUsageOutcome::Allow,
            ts,
        );
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CapabilityUsageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.occurred_at, ts);
    }

    #[test]
    fn event_json_no_extra_fields() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let value = serde_json::to_value(&event).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 10);
    }

    #[test]
    fn event_json_value_types() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let value = serde_json::to_value(&event).unwrap();
        assert!(value["format"].is_string());
        assert!(value["schema_version"].is_string());
        assert!(value["zone_id"].is_string());
        assert!(value["connector_id"].is_string());
        assert!(value["capability_id"].is_string());
        assert!(value["principal_id"].is_string());
        assert!(value["risk_tier"].is_string());
        assert!(value["operation"].is_string());
        assert!(value["outcome"].is_string());
        assert!(value["occurred_at"].is_number());
    }

    #[test]
    fn event_key_only_contains_zone_connector_capability() {
        let event = test_event(CapabilityUsageOutcome::Deny);
        let key = event.key();
        let key_json = serde_json::to_value(&key).unwrap();
        let key_obj = key_json.as_object().unwrap();
        assert_eq!(key_obj.len(), 3);
        assert!(key_obj.contains_key("zone_id"));
        assert!(key_obj.contains_key("connector_id"));
        assert!(key_obj.contains_key("capability_id"));
    }

    #[test]
    fn event_two_events_same_timestamp_different_outcome() {
        let e1 = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:a").expect("principal"),
            SafetyTier::Safe,
            OperationId::from_static("op.x"),
            CapabilityUsageOutcome::Allow,
            500,
        );
        let e2 = CapabilityUsageEvent::new(
            test_key(),
            PrincipalId::new("user:a").expect("principal"),
            SafetyTier::Safe,
            OperationId::from_static("op.x"),
            CapabilityUsageOutcome::Deny,
            500,
        );
        assert_eq!(e1.occurred_at, e2.occurred_at);
        assert_ne!(e1.outcome, e2.outcome);
        assert_eq!(e1.key(), e2.key());
    }

    #[test]
    fn key_used_as_hashmap_key_for_aggregation() {
        use std::collections::HashMap;
        let mut counts: HashMap<CapabilityUsageKey, u32> = HashMap::new();
        for _ in 0..10 {
            let event = test_event(CapabilityUsageOutcome::Allow);
            *counts.entry(event.key()).or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[&test_key()], 10);
    }

    #[test]
    fn key_used_as_hashmap_key_multiple_keys() {
        use std::collections::HashMap;
        let mut counts: HashMap<CapabilityUsageKey, u32> = HashMap::new();
        let k1 = test_key();
        let k2 = CapabilityUsageKey::new(
            ZoneId::private(),
            ConnectorId::from_static("fcp.b:rr:1"),
            CapabilityId::from_static("fcp.b.write"),
        );
        *counts.entry(k1).or_insert(0) += 3;
        *counts.entry(k2).or_insert(0) += 7;
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn event_deserialize_invalid_outcome_fails() {
        let raw = r#"{
            "format": "fcp-capability-usage",
            "schema_version": "1.0",
            "zone_id": "z:work",
            "connector_id": "fcp.x:rr:1",
            "capability_id": "fcp.x.r",
            "principal_id": "user:a",
            "risk_tier": "safe",
            "operation": "op.x",
            "outcome": "invalid_outcome",
            "occurred_at": 1
        }"#;
        let result = serde_json::from_str::<CapabilityUsageEvent>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn event_deserialize_invalid_risk_tier_fails() {
        let raw = r#"{
            "format": "fcp-capability-usage",
            "schema_version": "1.0",
            "zone_id": "z:work",
            "connector_id": "fcp.x:rr:1",
            "capability_id": "fcp.x.r",
            "principal_id": "user:a",
            "risk_tier": "ultra_dangerous",
            "operation": "op.x",
            "outcome": "allow",
            "occurred_at": 1
        }"#;
        let result = serde_json::from_str::<CapabilityUsageEvent>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn event_vec_collection() {
        let events: Vec<CapabilityUsageEvent> = vec![
            test_event(CapabilityUsageOutcome::Allow),
            test_event(CapabilityUsageOutcome::Deny),
            test_event(CapabilityUsageOutcome::Error),
        ];
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].outcome, CapabilityUsageOutcome::Allow);
        assert_eq!(events[1].outcome, CapabilityUsageOutcome::Deny);
        assert_eq!(events[2].outcome, CapabilityUsageOutcome::Error);
    }

    #[test]
    fn event_serialize_deserialize_vec() {
        let events = vec![
            test_event(CapabilityUsageOutcome::Allow),
            test_event(CapabilityUsageOutcome::Deny),
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<CapabilityUsageEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].outcome, CapabilityUsageOutcome::Allow);
        assert_eq!(decoded[1].outcome, CapabilityUsageOutcome::Deny);
    }

    #[test]
    fn key_serialize_deserialize_vec() {
        let keys = vec![
            test_key(),
            CapabilityUsageKey::new(
                ZoneId::private(),
                ConnectorId::from_static("fcp.y:rr:1"),
                CapabilityId::from_static("fcp.y.w"),
            ),
        ];
        let json = serde_json::to_string(&keys).unwrap();
        let decoded: Vec<CapabilityUsageKey> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], keys[0]);
        assert_eq!(decoded[1], keys[1]);
    }

    #[test]
    fn outcome_all_variants_count() {
        let all = [
            CapabilityUsageOutcome::Allow,
            CapabilityUsageOutcome::Deny,
            CapabilityUsageOutcome::Error,
        ];
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn event_format_never_empty() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert!(!event.format.is_empty());
    }

    #[test]
    fn event_schema_version_never_empty() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        assert!(!event.schema_version.is_empty());
    }

    #[test]
    fn event_key_roundtrip_through_json() {
        let key = test_key();
        let json = serde_json::to_string(&key).unwrap();
        let decoded: CapabilityUsageKey = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&decoded).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn event_roundtrip_preserves_format() {
        let event = test_event(CapabilityUsageOutcome::Allow);
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CapabilityUsageEvent = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&decoded).unwrap();
        let decoded2: CapabilityUsageEvent = serde_json::from_str(&json2).unwrap();
        assert_eq!(decoded2.format, event.format);
        assert_eq!(decoded2.schema_version, event.schema_version);
    }

    #[test]
    fn event_with_custom_format_preserved() {
        let raw = r#"{
            "format": "custom-format",
            "schema_version": "2.0",
            "zone_id": "z:work",
            "connector_id": "fcp.x:rr:1",
            "capability_id": "fcp.x.r",
            "principal_id": "user:a",
            "risk_tier": "safe",
            "operation": "op.x",
            "outcome": "allow",
            "occurred_at": 1
        }"#;
        let event: CapabilityUsageEvent = serde_json::from_str(raw).unwrap();
        assert_eq!(event.format, "custom-format");
        assert_eq!(event.schema_version, "2.0");
    }
}
