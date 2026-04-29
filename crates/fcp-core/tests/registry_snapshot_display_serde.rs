use fcp_core::{ConnectorId, ConnectorTarget, ConnectorVersion, ObjectId, RegistryEntry};

fn target(os: &str, arch: &str) -> ConnectorTarget {
    ConnectorTarget {
        os: os.to_string(),
        arch: arch.to_string(),
    }
}

fn object_id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn registry_snapshot_fixture() -> RegistryEntry {
    RegistryEntry::new(
        ConnectorId::from_static("connector:fcp.test"),
        ConnectorVersion::parse("1.2.3").expect("version"),
        target("linux", "amd64"),
        object_id(0x11),
        object_id(0x22),
    )
}

#[test]
fn registry_snapshot_display_pins_identity_version_and_target() {
    let snapshot = registry_snapshot_fixture();

    assert_eq!(snapshot.to_string(), "connector:fcp.test@1.2.3 linux-amd64");
    assert_eq!(
        snapshot
            .clone()
            .with_symbol_set_object_id(object_id(0x33))
            .to_string(),
        "connector:fcp.test@1.2.3 linux-amd64"
    );
}

#[test]
fn registry_snapshot_json_shape_omits_empty_symbol_set_and_roundtrips() {
    let snapshot = registry_snapshot_fixture();

    assert_eq!(
        serde_json::to_value(&snapshot).expect("serialize"),
        serde_json::json!({
            "connector_id": "connector:fcp.test",
            "version": "1.2.3",
            "target": {
                "os": "linux",
                "arch": "amd64",
            },
            "manifest_object_id": "11".repeat(32),
            "binary_object_id": "22".repeat(32),
        })
    );

    let json = serde_json::to_string(&snapshot).expect("serialize");
    let from_json: RegistryEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(from_json, snapshot);
    assert_eq!(from_json.to_string(), snapshot.to_string());
}

#[test]
fn registry_snapshot_json_and_cbor_roundtrip_preserve_symbol_set_and_display() {
    let snapshot = registry_snapshot_fixture().with_symbol_set_object_id(object_id(0x33));

    assert_eq!(
        serde_json::to_value(&snapshot).expect("serialize"),
        serde_json::json!({
            "connector_id": "connector:fcp.test",
            "version": "1.2.3",
            "target": {
                "os": "linux",
                "arch": "amd64",
            },
            "manifest_object_id": "11".repeat(32),
            "binary_object_id": "22".repeat(32),
            "symbol_set_object_id": "33".repeat(32),
        })
    );

    let json = serde_json::to_string(&snapshot).expect("serialize");
    let from_json: RegistryEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(from_json, snapshot);
    assert_eq!(from_json.to_string(), snapshot.to_string());

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&snapshot, &mut cbor).expect("encode");
    let from_cbor: RegistryEntry = ciborium::de::from_reader(cbor.as_slice()).expect("decode");
    assert_eq!(from_cbor, snapshot);
    assert_eq!(from_cbor.to_string(), snapshot.to_string());
}
