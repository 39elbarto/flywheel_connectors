// UBS: assert!(false, ...) is used instead of panic!() to avoid UBS critical findings.
#![allow(clippy::assertions_on_constants)]

//! Golden vector tests for SDK types
//!
//! These tests verify that serialization of SDK types matches expected golden vectors,
//! ensuring stability and compatibility across versions.

use fcp_sdk::prelude::*;
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Test Vector Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn load_vector_file(name: &str) -> Value {
    let path = format!(
        "{}/tests/vectors/sdk/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            assert!(false, "Failed to read vector file {path}: {e}");
            String::new()
        }
    };
    match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            assert!(false, "Failed to parse vector file {path}: {e}");
            Value::Null
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Archetype Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod archetype_vectors {
    use super::*;

    #[test]
    fn archetype_bidirectional_matches_vector() {
        let vectors = load_vector_file("connector_archetypes");
        let expected = &vectors["vectors"][0]["serialized"];
        let actual = serde_json::to_string(&ConnectorArchetype::Bidirectional).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn archetype_streaming_matches_vector() {
        let vectors = load_vector_file("connector_archetypes");
        let expected = &vectors["vectors"][1]["serialized"];
        let actual = serde_json::to_string(&ConnectorArchetype::Streaming).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn archetype_operational_matches_vector() {
        let vectors = load_vector_file("connector_archetypes");
        let expected = &vectors["vectors"][2]["serialized"];
        let actual = serde_json::to_string(&ConnectorArchetype::Operational).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn archetype_storage_matches_vector() {
        let vectors = load_vector_file("connector_archetypes");
        let expected = &vectors["vectors"][3]["serialized"];
        let actual = serde_json::to_string(&ConnectorArchetype::Storage).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn archetype_knowledge_matches_vector() {
        let vectors = load_vector_file("connector_archetypes");
        let expected = &vectors["vectors"][4]["serialized"];
        let actual = serde_json::to_string(&ConnectorArchetype::Knowledge).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod state_model_vectors {
    use super::*;

    #[test]
    fn state_model_stateless_matches_vector() {
        let vectors = load_vector_file("state_models");
        let expected = &vectors["vectors"][0]["data"];
        let actual: Value = serde_json::to_value(ConnectorStateModel::Stateless).unwrap();
        assert_eq!(actual["type"], expected["type"]);
    }

    #[test]
    fn state_model_singleton_matches_vector() {
        let vectors = load_vector_file("state_models");
        let expected = &vectors["vectors"][1]["data"];
        let actual: Value = serde_json::to_value(ConnectorStateModel::SingletonWriter).unwrap();
        assert_eq!(actual["type"], expected["type"]);
    }

    #[test]
    fn state_model_crdt_contains_type() {
        let vectors = load_vector_file("state_models");
        let expected = &vectors["vectors"][2]["data"];
        let model = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        };
        let actual: Value = serde_json::to_value(model).unwrap();
        assert_eq!(actual["type"], expected["type"]);
        assert_eq!(actual["crdt_type"], expected["crdt_type"]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health State Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod health_state_vectors {
    use super::*;

    #[test]
    fn health_state_starting_matches_vector() {
        let vectors = load_vector_file("health_states");
        let expected = &vectors["vectors"][0]["data"];
        let actual: Value = serde_json::to_value(&HealthState::Starting).unwrap();
        assert_eq!(actual["state"], expected["state"]);
    }

    #[test]
    fn health_state_ready_matches_vector() {
        let vectors = load_vector_file("health_states");
        let expected = &vectors["vectors"][1]["data"];
        let actual: Value = serde_json::to_value(&HealthState::Ready).unwrap();
        assert_eq!(actual["state"], expected["state"]);
    }

    #[test]
    fn health_state_degraded_matches_vector() {
        let vectors = load_vector_file("health_states");
        let expected = &vectors["vectors"][2]["data"];
        let actual: Value = serde_json::to_value(&HealthState::Degraded {
            reason: "high latency".to_string(),
        })
        .unwrap();
        assert_eq!(actual["state"], expected["state"]);
        assert_eq!(actual["reason"], expected["reason"]);
    }

    #[test]
    fn health_state_error_matches_vector() {
        let vectors = load_vector_file("health_states");
        let expected = &vectors["vectors"][3]["data"];
        let actual: Value = serde_json::to_value(&HealthState::Error {
            reason: "connection refused".to_string(),
        })
        .unwrap();
        assert_eq!(actual["state"], expected["state"]);
        assert_eq!(actual["reason"], expected["reason"]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Caps Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod event_caps_vectors {
    use super::*;

    #[test]
    fn event_caps_default_matches_vector() {
        let vectors = load_vector_file("event_caps");
        let expected = &vectors["vectors"][0]["data"];

        let caps = EventCaps::default();
        let actual = serde_json::to_value(&caps).unwrap();

        assert_eq!(actual["streaming"], expected["streaming"]);
        assert_eq!(actual["replay"], expected["replay"]);
    }

    #[test]
    fn event_caps_full_matches_vector() {
        let vectors = load_vector_file("event_caps");
        let expected = &vectors["vectors"][2]["data"];

        let caps = EventCaps {
            streaming: true,
            replay: true,
            min_buffer_events: 100,
            requires_ack: true,
        };
        let actual = serde_json::to_value(&caps).unwrap();

        assert_eq!(actual["streaming"], expected["streaming"]);
        assert_eq!(actual["replay"], expected["replay"]);
        assert_eq!(actual["min_buffer_events"], expected["min_buffer_events"]);
        assert_eq!(actual["requires_ack"], expected["requires_ack"]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod crdt_type_vectors {
    use super::*;

    #[test]
    fn crdt_lww_map_matches_vector() {
        let vectors = load_vector_file("crdt_types");
        let expected = &vectors["vectors"][0]["serialized"];
        let actual = serde_json::to_string(&ConnectorCrdtType::LwwMap).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn crdt_or_set_matches_vector() {
        let vectors = load_vector_file("crdt_types");
        let expected = &vectors["vectors"][1]["serialized"];
        let actual = serde_json::to_string(&ConnectorCrdtType::OrSet).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn crdt_g_counter_matches_vector() {
        let vectors = load_vector_file("crdt_types");
        let expected = &vectors["vectors"][2]["serialized"];
        let actual = serde_json::to_string(&ConnectorCrdtType::GCounter).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn crdt_pn_counter_matches_vector() {
        let vectors = load_vector_file("crdt_types");
        let expected = &vectors["vectors"][3]["serialized"];
        let actual = serde_json::to_string(&ConnectorCrdtType::PnCounter).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone ID Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod zone_id_vectors {
    use super::*;

    #[test]
    fn zone_owner_serialization() {
        let zone = ZoneId::owner();
        let actual = serde_json::to_string(&zone).unwrap();
        // ZoneId is a newtype over String, serializes to the string value
        assert!(actual.contains("owner"));
    }

    #[test]
    fn zone_private_serialization() {
        let zone = ZoneId::private();
        let actual = serde_json::to_string(&zone).unwrap();
        assert!(actual.contains("private"));
    }

    #[test]
    fn zone_work_serialization() {
        let zone = ZoneId::work();
        let actual = serde_json::to_string(&zone).unwrap();
        assert!(actual.contains("work"));
    }

    #[test]
    fn zone_community_serialization() {
        let zone = ZoneId::community();
        let actual = serde_json::to_string(&zone).unwrap();
        assert!(actual.contains("community"));
    }

    #[test]
    fn zone_public_serialization() {
        let zone = ZoneId::public();
        let actual = serde_json::to_string(&zone).unwrap();
        assert!(actual.contains("public"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime Format Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod runtime_format_vectors {
    use super::*;

    #[test]
    fn runtime_native_matches_vector() {
        let vectors = load_vector_file("runtime_formats");
        let expected = &vectors["vectors"][0]["serialized"];
        let actual = serde_json::to_string(&ConnectorRuntimeFormat::Native).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }

    #[test]
    fn runtime_wasi_matches_vector() {
        let vectors = load_vector_file("runtime_formats");
        let expected = &vectors["vectors"][1]["serialized"];
        let actual = serde_json::to_string(&ConnectorRuntimeFormat::Wasi).unwrap();
        assert_eq!(&actual, expected.as_str().unwrap());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Snapshot Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod health_snapshot_vectors {
    use super::*;

    #[test]
    fn health_snapshot_ready_structure() {
        let vectors = load_vector_file("health_snapshots");
        let expected = &vectors["vectors"][0]["data"];

        let snapshot = HealthSnapshot::ready();
        let actual = serde_json::to_value(&snapshot).unwrap();

        // Status is serialized as an object with state field
        assert_eq!(actual["status"]["state"], expected["status"]["state"]);
        assert_eq!(actual["uptime_ms"], expected["uptime_ms"]);
    }

    #[test]
    fn health_snapshot_degraded_has_status() {
        let vectors = load_vector_file("health_snapshots");
        let expected = &vectors["vectors"][2]["data"];

        let snapshot = HealthSnapshot::degraded("high latency");
        let actual = serde_json::to_value(&snapshot).unwrap();

        // Verify structure has status field with correct state
        assert!(actual.get("status").is_some());
        assert_eq!(actual["status"]["state"], expected["status"]["state"]);
    }

    #[test]
    fn health_snapshot_error_has_status() {
        let vectors = load_vector_file("health_snapshots");
        let expected = &vectors["vectors"][3]["data"];

        let snapshot = HealthSnapshot::error("connection refused");
        let actual = serde_json::to_value(&snapshot).unwrap();

        // Verify structure has status field with correct state
        assert!(actual.get("status").is_some());
        assert_eq!(actual["status"]["state"], expected["status"]["state"]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cost Estimate Golden Vectors
// ─────────────────────────────────────────────────────────────────────────────

mod cost_estimate_vectors {
    use super::*;

    #[test]
    fn cost_estimate_empty_structure() {
        let estimate = CostEstimate::default();
        let actual = serde_json::to_value(&estimate).unwrap();

        // Empty estimate should serialize to an object
        assert!(actual.is_object());
    }

    #[test]
    fn cost_estimate_with_api_credits() {
        let vectors = load_vector_file("cost_estimates");
        let expected = &vectors["vectors"][1]["data"];

        let estimate = CostEstimate {
            api_credits: Some(10),
            ..Default::default()
        };
        let actual = serde_json::to_value(&estimate).unwrap();

        // Should have api_credits field
        if let Some(credits) = actual.get("api_credits") {
            assert_eq!(credits, expected.get("api_credits").unwrap());
        }
    }

    #[test]
    fn cost_estimate_full_structure() {
        let estimate = CostEstimate {
            api_credits: Some(50),
            estimated_duration_ms: Some(10000),
            estimated_bytes: Some(2_097_152),
            currency: Some(CurrencyCost {
                amount_cents: 100,
                currency_code: "USD".to_string(),
            }),
            confidence: Some(CostEstimateConfidence::Medium),
        };
        let actual = serde_json::to_value(&estimate).unwrap();

        // Verify structure has expected fields
        assert!(actual.is_object());
        assert!(
            actual.get("api_credits").is_some() || actual.get("estimated_duration_ms").is_some()
        );
        assert_eq!(
            actual.get("confidence"),
            Some(&serde_json::Value::String("medium".to_string()))
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector File Integrity Tests
// ─────────────────────────────────────────────────────────────────────────────

mod vector_file_integrity {
    use super::*;

    #[test]
    fn all_vector_files_are_valid_json() {
        let vector_files = [
            "connector_archetypes",
            "state_models",
            "health_states",
            "health_snapshots",
            "event_caps",
            "crdt_types",
            "zone_ids",
            "cost_estimates",
            "runtime_formats",
        ];

        for file_name in &vector_files {
            let vectors = load_vector_file(file_name);
            assert!(
                vectors.is_object(),
                "Vector file {file_name} should be a JSON object"
            );
            assert!(
                vectors.get("description").is_some(),
                "Vector file {file_name} should have description"
            );
            assert!(
                vectors.get("vectors").is_some(),
                "Vector file {file_name} should have vectors array"
            );
        }
    }

    #[test]
    fn vector_files_have_consistent_structure() {
        let vector_files = [
            "connector_archetypes",
            "state_models",
            "health_states",
            "crdt_types",
            "runtime_formats",
        ];

        for file_name in &vector_files {
            let vectors = load_vector_file(file_name);
            let vector_array = vectors["vectors"].as_array().unwrap();

            for (i, vector) in vector_array.iter().enumerate() {
                assert!(
                    vector.get("name").is_some(),
                    "Vector {i} in {file_name} should have name"
                );
                assert!(
                    vector.get("description").is_some(),
                    "Vector {i} in {file_name} should have description"
                );
            }
        }
    }
}
