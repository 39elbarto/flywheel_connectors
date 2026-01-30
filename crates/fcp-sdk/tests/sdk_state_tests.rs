//! SDK State Model Tests
//!
//! Tests for connector state model types including:
//! - State model discriminants (Stateless, `SingletonWriter`, Crdt)
//! - CRDT type handling
//! - State model serialization
//! - Archetype associations

use std::sync::Arc;

use fcp_cbor::SchemaId;
use fcp_core::{ObjectHeader, Signature};

#[cfg(feature = "cursor-store-object-store")]
use fcp_core::ObjectIdKey;
use fcp_sdk::prelude::*;
use semver::Version;

#[cfg(feature = "cursor-store-object-store")]
use fcp_sdk::runtime::ObjectStoreCursorBackend;
#[cfg(feature = "cursor-store-object-store")]
use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig};

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorStateModel Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_stateless() {
    let model = ConnectorStateModel::Stateless;

    assert!(matches!(model, ConnectorStateModel::Stateless));
}

#[test]
fn test_state_model_singleton_writer() {
    let model = ConnectorStateModel::SingletonWriter;

    assert!(matches!(model, ConnectorStateModel::SingletonWriter));
}

#[test]
fn test_state_model_crdt() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };

    assert!(matches!(model, ConnectorStateModel::Crdt { .. }));
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Display Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_debug_stateless() {
    let model = ConnectorStateModel::Stateless;
    let debug = format!("{model:?}");
    assert!(debug.contains("Stateless"));
}

#[test]
fn test_state_model_debug_singleton_writer() {
    let model = ConnectorStateModel::SingletonWriter;
    let debug = format!("{model:?}");
    assert!(debug.contains("SingletonWriter"));
}

#[test]
fn test_state_model_debug_crdt() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    let debug = format!("{model:?}");
    assert!(debug.contains("Crdt"));
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crdt_type_as_str() {
    assert_eq!(ConnectorCrdtType::LwwMap.as_str(), "lww_map");
    assert_eq!(ConnectorCrdtType::OrSet.as_str(), "or_set");
    assert_eq!(ConnectorCrdtType::GCounter.as_str(), "g_counter");
    assert_eq!(ConnectorCrdtType::PnCounter.as_str(), "pn_counter");
}

#[test]
fn test_crdt_type_variants() {
    let lww = ConnectorCrdtType::LwwMap;
    let or_set = ConnectorCrdtType::OrSet;
    let g_counter = ConnectorCrdtType::GCounter;
    let pn_counter = ConnectorCrdtType::PnCounter;

    assert!(matches!(lww, ConnectorCrdtType::LwwMap));
    assert!(matches!(or_set, ConnectorCrdtType::OrSet));
    assert!(matches!(g_counter, ConnectorCrdtType::GCounter));
    assert!(matches!(pn_counter, ConnectorCrdtType::PnCounter));
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_serialize_stateless() {
    let model = ConnectorStateModel::Stateless;
    let json = serde_json::to_value(model).expect("serialize should work");

    assert_eq!(json["type"], "stateless");
}

#[test]
fn test_state_model_serialize_singleton_writer() {
    let model = ConnectorStateModel::SingletonWriter;
    let json = serde_json::to_value(model).expect("serialize should work");

    assert_eq!(json["type"], "singleton_writer");
}

#[test]
fn test_state_model_serialize_crdt() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    let json = serde_json::to_value(model).expect("serialize should work");

    assert_eq!(json["type"], "crdt");
    assert_eq!(json["crdt_type"], "lww_map");
}

// ─────────────────────────────────────────────────────────────────────────────
// CursorStore Tests
// ─────────────────────────────────────────────────────────────────────────────

fn test_header(created_at: u64) -> ObjectHeader {
    ObjectHeader {
        schema: SchemaId::new("fcp.test", "ConnectorStateObject", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at,
        provenance: Provenance {
            origin_zone: ZoneId::work(),
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        },
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

#[cfg(feature = "cursor-store-object-store")]
fn object_store_header(created_at: u64, zone_id: ZoneId) -> ObjectHeader {
    ObjectHeader {
        schema: SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at,
        provenance: Provenance {
            origin_zone: zone_id,
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        },
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

#[test]
fn cursor_store_commit_and_load() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    let cursor = CursorState {
        offset: Some(10),
        last_seen_id: Some("id-10".to_string()),
        watermark: Some(100),
    };

    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x11; 32]),
    };

    let object_id = store
        .commit_cursor(
            cursor.clone(),
            test_header(1_700_000_000),
            lease,
            Signature::zero(),
        )
        .expect("commit should succeed");

    assert_eq!(store.head(), Some(object_id));

    let loaded = store
        .load_cursor()
        .expect("load should succeed")
        .expect("cursor should exist");
    assert_eq!(loaded, cursor);
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_store_object_store_roundtrip() {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let object_id_key = ObjectIdKey::from_bytes([0xA5; 32]);
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();

    let backend = ObjectStoreCursorBackend::new(
        object_store,
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    );
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    let cursor = CursorState {
        offset: Some(42),
        last_seen_id: Some("id-42".to_string()),
        watermark: Some(420),
    };

    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x11; 32]),
    };

    let object_id = store
        .commit_cursor(
            cursor.clone(),
            object_store_header(1_700_100_000, ZoneId::work()),
            lease,
            Signature::zero(),
        )
        .expect("commit should succeed");

    assert_eq!(store.head(), Some(object_id));

    let loaded = store
        .load_cursor()
        .expect("load should succeed")
        .expect("cursor should exist");
    assert_eq!(loaded, cursor);
}

#[test]
fn cursor_store_rejects_offset_regression() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x22; 32]),
    };

    let cursor = CursorState {
        offset: Some(10),
        last_seen_id: Some("id-10".to_string()),
        watermark: Some(100),
    };

    store
        .commit_cursor(cursor, test_header(1_700_000_001), lease, Signature::zero())
        .expect("initial commit should succeed");

    let regressed = CursorState {
        offset: Some(9),
        last_seen_id: Some("id-9".to_string()),
        watermark: Some(100),
    };

    let err = store
        .commit_cursor(
            regressed,
            test_header(1_700_000_002),
            CursorLease {
                lease_seq: 2,
                lease_object_id: ObjectId::from_bytes([0x23; 32]),
            },
            Signature::zero(),
        )
        .expect_err("offset regression should be rejected");

    assert!(matches!(err, CursorStoreError::OffsetRegression { .. }));
}

#[test]
fn cursor_store_rejects_stale_lease_seq() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    store
        .commit_cursor(
            CursorState {
                offset: Some(1),
                last_seen_id: None,
                watermark: None,
            },
            test_header(1_700_000_010),
            CursorLease {
                lease_seq: 5,
                lease_object_id: ObjectId::from_bytes([0x33; 32]),
            },
            Signature::zero(),
        )
        .expect("initial commit should succeed");

    let err = store
        .commit_cursor(
            CursorState {
                offset: Some(2),
                last_seen_id: None,
                watermark: None,
            },
            test_header(1_700_000_011),
            CursorLease {
                lease_seq: 4,
                lease_object_id: ObjectId::from_bytes([0x34; 32]),
            },
            Signature::zero(),
        )
        .expect_err("stale lease_seq should be rejected");

    assert!(matches!(err, CursorStoreError::StaleLeaseSeq { .. }));
}

#[test]
fn cursor_store_rejects_watermark_regression() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    store
        .commit_cursor(
            CursorState {
                offset: Some(10),
                last_seen_id: None,
                watermark: Some(200),
            },
            test_header(1_700_000_020),
            CursorLease {
                lease_seq: 1,
                lease_object_id: ObjectId::from_bytes([0x35; 32]),
            },
            Signature::zero(),
        )
        .expect("initial commit should succeed");

    let err = store
        .commit_cursor(
            CursorState {
                offset: Some(11),
                last_seen_id: None,
                watermark: Some(100),
            },
            test_header(1_700_000_021),
            CursorLease {
                lease_seq: 2,
                lease_object_id: ObjectId::from_bytes([0x36; 32]),
            },
            Signature::zero(),
        )
        .expect_err("watermark regression should be rejected");

    assert!(matches!(err, CursorStoreError::WatermarkRegression { .. }));
}

#[test]
fn cursor_store_failover_rejects_stale_writer() {
    let backend = Arc::new(InMemoryCursorStoreBackend::new());
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store_a = CursorStore::new(Arc::clone(&backend), connector_id.clone(), zone_id.clone());
    let mut store_b = CursorStore::new(Arc::clone(&backend), connector_id, zone_id);

    store_a
        .commit_cursor(
            CursorState {
                offset: Some(1),
                last_seen_id: None,
                watermark: Some(10),
            },
            test_header(1_700_000_030),
            CursorLease {
                lease_seq: 1,
                lease_object_id: ObjectId::from_bytes([0x41; 32]),
            },
            Signature::zero(),
        )
        .expect("first writer commit should succeed");

    let loaded = store_b
        .load_cursor()
        .expect("second writer should load cursor")
        .expect("cursor should be present");
    assert_eq!(loaded.offset, Some(1));

    store_b
        .commit_cursor(
            CursorState {
                offset: Some(2),
                last_seen_id: None,
                watermark: Some(20),
            },
            test_header(1_700_000_031),
            CursorLease {
                lease_seq: 2,
                lease_object_id: ObjectId::from_bytes([0x42; 32]),
            },
            Signature::zero(),
        )
        .expect("second writer commit should succeed");

    let refreshed = store_a
        .load_cursor()
        .expect("first writer reload should succeed")
        .expect("cursor should be present");
    assert_eq!(refreshed.offset, Some(2));

    let err = store_a
        .commit_cursor(
            CursorState {
                offset: Some(3),
                last_seen_id: None,
                watermark: Some(30),
            },
            test_header(1_700_000_032),
            CursorLease {
                lease_seq: 1,
                lease_object_id: ObjectId::from_bytes([0x43; 32]),
            },
            Signature::zero(),
        )
        .expect_err("stale lease after failover should be rejected");

    assert!(matches!(err, CursorStoreError::StaleLeaseSeq { .. }));
}

#[test]
fn test_state_model_deserialize_stateless() {
    let json = r#"{"type": "stateless"}"#;
    let model: ConnectorStateModel = serde_json::from_str(json).expect("deserialize should work");

    assert!(matches!(model, ConnectorStateModel::Stateless));
}

#[test]
fn test_state_model_deserialize_singleton_writer() {
    let json = r#"{"type": "singleton_writer"}"#;
    let model: ConnectorStateModel = serde_json::from_str(json).expect("deserialize should work");

    assert!(matches!(model, ConnectorStateModel::SingletonWriter));
}

#[test]
fn test_state_model_deserialize_crdt() {
    let json = r#"{"type": "crdt", "crdt_type": "lww_map"}"#;
    let model: ConnectorStateModel = serde_json::from_str(json).expect("deserialize should work");

    assert!(matches!(model, ConnectorStateModel::Crdt { .. }));
}

#[test]
fn test_state_model_roundtrip() {
    let models = vec![
        ConnectorStateModel::Stateless,
        ConnectorStateModel::SingletonWriter,
        ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        },
    ];

    for model in models {
        let json = serde_json::to_string(&model).expect("serialize should work");
        let recovered: ConnectorStateModel =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(model, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crdt_type_serialize() {
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::LwwMap).unwrap(),
        "lww_map"
    );
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::OrSet).unwrap(),
        "or_set"
    );
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::GCounter).unwrap(),
        "g_counter"
    );
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::PnCounter).unwrap(),
        "pn_counter"
    );
}

#[test]
fn test_crdt_type_deserialize() {
    let types = [
        ("\"lww_map\"", ConnectorCrdtType::LwwMap),
        ("\"or_set\"", ConnectorCrdtType::OrSet),
        ("\"g_counter\"", ConnectorCrdtType::GCounter),
        ("\"pn_counter\"", ConnectorCrdtType::PnCounter),
    ];

    for (json, expected) in types {
        let crdt_type: ConnectorCrdtType =
            serde_json::from_str(json).expect("deserialize should work");
        assert_eq!(crdt_type, expected);
    }
}

#[test]
fn test_crdt_type_roundtrip() {
    let types = vec![
        ConnectorCrdtType::LwwMap,
        ConnectorCrdtType::OrSet,
        ConnectorCrdtType::GCounter,
        ConnectorCrdtType::PnCounter,
    ];

    for crdt_type in types {
        let json = serde_json::to_string(&crdt_type).expect("serialize should work");
        let recovered: ConnectorCrdtType =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(crdt_type, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Archetype Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_archetype_bidirectional() {
    let archetype = ConnectorArchetype::Bidirectional;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "bidirectional");
}

#[test]
fn test_archetype_streaming() {
    let archetype = ConnectorArchetype::Streaming;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "streaming");
}

#[test]
fn test_archetype_operational() {
    let archetype = ConnectorArchetype::Operational;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "operational");
}

#[test]
fn test_archetype_storage() {
    let archetype = ConnectorArchetype::Storage;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "storage");
}

#[test]
fn test_archetype_knowledge() {
    let archetype = ConnectorArchetype::Knowledge;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "knowledge");
}

#[test]
fn test_archetype_deserialize() {
    let archetypes = [
        ("\"bidirectional\"", ConnectorArchetype::Bidirectional),
        ("\"streaming\"", ConnectorArchetype::Streaming),
        ("\"operational\"", ConnectorArchetype::Operational),
        ("\"storage\"", ConnectorArchetype::Storage),
        ("\"knowledge\"", ConnectorArchetype::Knowledge),
    ];

    for (json, expected) in archetypes {
        let archetype: ConnectorArchetype =
            serde_json::from_str(json).expect("deserialize should work");
        assert_eq!(archetype, expected);
    }
}

#[test]
fn test_archetype_roundtrip() {
    let archetypes = vec![
        ConnectorArchetype::Bidirectional,
        ConnectorArchetype::Streaming,
        ConnectorArchetype::Operational,
        ConnectorArchetype::Storage,
        ConnectorArchetype::Knowledge,
    ];

    for archetype in archetypes {
        let json = serde_json::to_string(&archetype).expect("serialize should work");
        let recovered: ConnectorArchetype =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(archetype, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime Format Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_runtime_format_native() {
    let format = ConnectorRuntimeFormat::Native;
    let json = serde_json::to_value(format).expect("serialize should work");
    assert_eq!(json, "native");
}

#[test]
fn test_runtime_format_wasi() {
    let format = ConnectorRuntimeFormat::Wasi;
    let json = serde_json::to_value(format).expect("serialize should work");
    assert_eq!(json, "wasi");
}

#[test]
fn test_runtime_format_deserialize() {
    let formats = [
        ("\"native\"", ConnectorRuntimeFormat::Native),
        ("\"wasi\"", ConnectorRuntimeFormat::Wasi),
    ];

    for (json, expected) in formats {
        let format: ConnectorRuntimeFormat =
            serde_json::from_str(json).expect("deserialize should work");
        assert_eq!(format, expected);
    }
}

#[test]
fn test_runtime_format_roundtrip() {
    let formats = vec![ConnectorRuntimeFormat::Native, ConnectorRuntimeFormat::Wasi];

    for format in formats {
        let json = serde_json::to_string(&format).expect("serialize should work");
        let recovered: ConnectorRuntimeFormat =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(format, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Equality Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_equality() {
    let stateless1 = ConnectorStateModel::Stateless;
    let stateless2 = ConnectorStateModel::Stateless;
    assert_eq!(stateless1, stateless2);

    let singleton1 = ConnectorStateModel::SingletonWriter;
    let singleton2 = ConnectorStateModel::SingletonWriter;
    assert_eq!(singleton1, singleton2);

    let crdt1 = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    let crdt2 = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    assert_eq!(crdt1, crdt2);
}

#[test]
fn test_state_model_not_equal_different_variants() {
    let stateless = ConnectorStateModel::Stateless;
    let singleton = ConnectorStateModel::SingletonWriter;
    let crdt = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };

    assert_ne!(stateless, singleton);
    assert_ne!(stateless, crdt);
    assert_ne!(singleton, crdt);
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Equality and Hash Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crdt_type_equality() {
    assert_eq!(ConnectorCrdtType::LwwMap, ConnectorCrdtType::LwwMap);
    assert_eq!(ConnectorCrdtType::OrSet, ConnectorCrdtType::OrSet);
    assert_eq!(ConnectorCrdtType::GCounter, ConnectorCrdtType::GCounter);
    assert_eq!(ConnectorCrdtType::PnCounter, ConnectorCrdtType::PnCounter);
}

#[test]
fn test_crdt_type_not_equal() {
    assert_ne!(ConnectorCrdtType::LwwMap, ConnectorCrdtType::OrSet);
    assert_ne!(ConnectorCrdtType::GCounter, ConnectorCrdtType::PnCounter);
}

#[test]
fn test_crdt_type_hashable() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(ConnectorCrdtType::LwwMap);
    set.insert(ConnectorCrdtType::OrSet);
    set.insert(ConnectorCrdtType::GCounter);
    set.insert(ConnectorCrdtType::PnCounter);

    assert_eq!(set.len(), 4);
    assert!(set.contains(&ConnectorCrdtType::LwwMap));
    assert!(set.contains(&ConnectorCrdtType::OrSet));
}

// ─────────────────────────────────────────────────────────────────────────────
// Clone and Copy Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[allow(clippy::clone_on_copy)] // Explicitly testing clone behavior
fn test_state_model_clone() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };

    let cloned = model.clone();
    assert_eq!(model, cloned);
}

#[test]
fn test_state_model_copy() {
    let model = ConnectorStateModel::Stateless;
    let copied = model;
    assert_eq!(model, copied);
}

#[test]
fn test_crdt_type_copy() {
    let crdt = ConnectorCrdtType::LwwMap;
    let copied = crdt;
    assert_eq!(crdt, copied);
}

#[test]
fn test_archetype_copy() {
    let archetype = ConnectorArchetype::Operational;
    let copied = archetype;
    assert_eq!(archetype, copied);
}

#[test]
fn test_runtime_format_copy() {
    let format = ConnectorRuntimeFormat::Native;
    let copied = format;
    assert_eq!(format, copied);
}
