//! Dedicated `BlueBubbles` connector wrapper.
//!
//! This reuses the existing `BlueBubbles`-backed `iMessage` implementation while
//! exposing a connector identity and manifest that are explicit about the
//! bridge surface itself.

#![forbid(unsafe_code)]

pub mod error;

use fcp_imessage::BlueBubblesConnector;

pub const CONNECTOR_ID: &str = "fcp.bluebubbles";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[must_use]
pub fn new_connector() -> BlueBubblesConnector {
    BlueBubblesConnector::with_connector_metadata(CONNECTOR_ID, MANIFEST_TOML)
}

pub use fcp_imessage::BlueBubblesConnector as SharedBlueBubblesConnector;

#[cfg(test)]
mod tests {
    use fcp_prelude::FcpConnector;

    use super::*;

    #[test]
    fn wrapper_uses_dedicated_connector_id() {
        let connector = new_connector();
        assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    }

    #[test]
    fn connector_id_constant_matches_manifest() {
        assert_eq!(CONNECTOR_ID, "fcp.bluebubbles");
    }

    #[test]
    fn wrapper_exposes_existing_operation_catalog() {
        let connector = new_connector();
        let introspection = connector.introspect();
        assert!(
            introspection
                .operations
                .iter()
                .any(|operation| operation.id.as_str() == "imessage.send_message")
        );
    }

    #[test]
    fn introspect_includes_all_shared_operations() {
        let connector = new_connector();
        let introspection = connector.introspect();
        let expected_ops = [
            "imessage.send_message",
            "imessage.get_chats",
            "imessage.get_chat",
            "imessage.get_messages",
            "imessage.sync_events",
            "imessage.download_attachment",
            "imessage.mark_read",
            "imessage.register_webhook",
            "imessage.list_webhooks",
            "imessage.unregister_webhook",
            "imessage.ingest_webhook_event",
            "imessage.get_server_info",
        ];
        for op in &expected_ops {
            assert!(
                introspection
                    .operations
                    .iter()
                    .any(|o| o.id.as_str() == *op),
                "missing operation: {op}"
            );
        }
        assert_eq!(introspection.operations.len(), expected_ops.len());
    }

    #[test]
    fn manifest_toml_is_valid_utf8_and_nonempty() {
        assert!(!MANIFEST_TOML.is_empty());
        assert!(MANIFEST_TOML.contains("fcp.bluebubbles"));
        assert!(MANIFEST_TOML.contains("[connector]"));
    }

    #[test]
    fn manifest_declares_operational_archetype() {
        assert!(MANIFEST_TOML.contains("operational"));
    }

    #[test]
    fn manifest_uses_private_zone() {
        assert!(MANIFEST_TOML.contains("z:private"));
    }

    #[test]
    fn default_health_is_not_ready_before_configure() {
        let connector = new_connector();
        let result = fcp_async_core::runtime::block_on_sync(async { connector.health().await });
        let snapshot = result.expect("health() should not fail");
        assert!(
            !matches!(snapshot.status, fcp_core::HealthState::Ready),
            "connector should not report ready before configure"
        );
    }

    #[test]
    fn doctor_returns_nonempty_checks() {
        let connector = new_connector();
        let doctor = connector.doctor();
        assert!(
            !doctor.checks.is_empty(),
            "doctor should produce at least one diagnostic check"
        );
    }

    #[test]
    fn doctor_reports_not_passed_before_configure() {
        let connector = new_connector();
        let doctor = connector.doctor();
        assert!(
            !doctor.passed,
            "doctor should report not-passed before connector is configured"
        );
    }

    #[test]
    fn wrapper_does_not_expose_imessage_id() {
        let connector = new_connector();
        assert_ne!(connector.id().as_str(), "fcp.imessage");
    }

    #[test]
    fn new_connector_is_deterministic() {
        let c1 = new_connector();
        let c2 = new_connector();
        assert_eq!(c1.id().as_str(), c2.id().as_str());
        assert_eq!(
            c1.introspect().operations.len(),
            c2.introspect().operations.len()
        );
    }

    #[test]
    fn shared_connector_type_is_reexported() {
        let _: SharedBlueBubblesConnector = new_connector();
    }

    #[test]
    fn introspect_operations_have_nonempty_summaries() {
        let connector = new_connector();
        let introspection = connector.introspect();
        for op in &introspection.operations {
            assert!(
                !op.summary.is_empty(),
                "operation {} has empty summary",
                op.id
            );
        }
    }

    #[test]
    fn send_operation_is_classified_risky() {
        let connector = new_connector();
        let introspection = connector.introspect();
        let send_op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == "imessage.send_message")
            .expect("send_message operation should exist");
        assert_eq!(
            send_op.safety_tier,
            fcp_core::SafetyTier::Risky,
            "send_message should be classified as Risky"
        );
    }

    #[test]
    fn read_operations_are_classified_safe() {
        let connector = new_connector();
        let introspection = connector.introspect();
        let read_ops = [
            "imessage.get_chats",
            "imessage.get_chat",
            "imessage.get_messages",
        ];
        for op_id in &read_ops {
            let op = introspection
                .operations
                .iter()
                .find(|o| o.id.as_str() == *op_id)
                .expect("read operation should exist");
            assert_eq!(
                op.safety_tier,
                fcp_core::SafetyTier::Safe,
                "{op_id} should be classified as Safe"
            );
        }
    }

    #[test]
    fn operations_declare_nonempty_capabilities() {
        let connector = new_connector();
        let introspection = connector.introspect();
        for op in &introspection.operations {
            assert!(
                !op.capability.as_str().is_empty(),
                "operation {} should declare a capability",
                op.id
            );
        }
    }

    #[test]
    fn manifest_contains_network_constraints() {
        assert!(
            MANIFEST_TOML.contains("network_constraints")
                || MANIFEST_TOML.contains("[provides.network_constraints]"),
            "manifest should declare network constraints"
        );
    }

    #[test]
    fn manifest_contains_sandbox_config() {
        assert!(MANIFEST_TOML.contains("[sandbox]"));
    }

    #[test]
    fn manifest_restricts_to_localhost() {
        assert!(
            MANIFEST_TOML.contains("127.0.0.1") || MANIFEST_TOML.contains("localhost"),
            "BlueBubbles connects to a local bridge; manifest should restrict to localhost"
        );
    }

    #[test]
    fn manifest_declares_capabilities() {
        assert!(MANIFEST_TOML.contains("[capabilities]"));
    }

    #[test]
    fn manifest_forbids_privileged_capabilities() {
        assert!(
            MANIFEST_TOML.contains("system.privileged"),
            "manifest should list system.privileged in forbidden capabilities"
        );
    }

    #[test]
    fn manifest_denies_exec() {
        assert!(
            MANIFEST_TOML.contains("deny_exec = true"),
            "manifest should deny exec for sandbox safety"
        );
    }

    #[test]
    fn introspect_operation_ids_are_unique() {
        let connector = new_connector();
        let introspection = connector.introspect();
        let mut seen = std::collections::HashSet::new();
        for op in &introspection.operations {
            assert!(
                seen.insert(op.id.as_str()),
                "duplicate operation id: {}",
                op.id
            );
        }
    }

    #[test]
    fn operations_have_valid_idempotency() {
        let connector = new_connector();
        let introspection = connector.introspect();
        for op in &introspection.operations {
            let idempotency_str = format!("{:?}", op.idempotency);
            assert!(
                ["Strict", "BestEffort", "None"]
                    .iter()
                    .any(|v| idempotency_str.contains(v)),
                "operation {} has unexpected idempotency: {idempotency_str}",
                op.id
            );
        }
    }
}
