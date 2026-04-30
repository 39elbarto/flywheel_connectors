//! Pin `ConnectorBinaryTransmissionInfo` serde shape — the closest
//! analogue to "ConnectorBundleSize"
//! (flywheel_connectors-mrnib).
//!
//! Bead asks for `ConnectorBundleSize serde JSON+CBOR roundtrip`.
//! No type literally named `ConnectorBundleSize` exists in fcp-core.
//! The closest "connector bundle size descriptor" is
//! `ConnectorBinaryTransmissionInfo` (connector_artifacts.rs:112) —
//! the portable transmission descriptor mirroring the symbol-layer
//! `OTI` (Object Transmission Information) fields:
//!
//!  - `transfer_length: u64` — total object size in bytes
//!  - `symbol_size: u16` — symbol size in bytes
//!  - `source_blocks: u8` — number of source blocks
//!  - `sub_blocks: u16` — number of sub-blocks
//!  - `alignment: u8` — symbol alignment
//!  - `payload_hash: Option<[u8; 32]>` — optional end-to-end hash
//!
//! Used in fixtures across signed_package_catalog_serde_roundtrip.rs
//! and connector_bundle_serde_extended.rs but NOT yet pinned for its
//! own serde shape. This test pins:
//!
//!   1. **6-field JSON shape** when payload_hash is Some.
//!   2. **payload_hash omitted via skip_serializing_if when None**.
//!   3. **payload_hash defaults to None** when missing from wire form
//!      via `#[serde(default)]`.
//!   4. **JSON round-trip** preserves all fields.
//!   5. **CBOR round-trip** preserves all fields.
//!   6. **Boundary values** for each numeric field (0 + max for u64,
//!      u16, u8) round-trip.
//!   7. **payload_hash JSON form is array of 32 numbers** (no
//!      hex_or_bytes serde adapter on this field — pinned vs the
//!      hex-string form used elsewhere on `[u8; 32]`).
//!   8. **CBOR payload_hash form** — sequence of 32 bytes in CBOR.
//!   9. **Cross-format consistency**: JSON and CBOR decode to the
//!      same value.
//!  10. **Nested usage in `ConnectorBinarySymbolSet`** preserves
//!      the transmission-info struct through round-trip.

use fcp_core::{
    ConnectorBinarySymbolSet, ConnectorBinaryTransmissionInfo, ConnectorTarget, ObjectId,
};

fn fixture_no_payload_hash() -> ConnectorBinaryTransmissionInfo {
    ConnectorBinaryTransmissionInfo::new(1024, 256, 4, 1, 1)
}

fn fixture_with_payload_hash() -> ConnectorBinaryTransmissionInfo {
    let mut hash = [0u8; 32];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = i as u8;
    }
    fixture_no_payload_hash().with_payload_hash(hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. 6-field JSON shape with payload_hash present
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn full_json_shape_pinned_with_payload_hash_present() {
    let info = fixture_with_payload_hash();
    let value = serde_json::to_value(&info).expect("serialize");
    let obj = value
        .as_object()
        .expect("ConnectorBinaryTransmissionInfo is JSON object");

    assert_eq!(
        obj.get("transfer_length").and_then(|v| v.as_u64()),
        Some(1024)
    );
    assert_eq!(obj.get("symbol_size").and_then(|v| v.as_u64()), Some(256));
    assert_eq!(obj.get("source_blocks").and_then(|v| v.as_u64()), Some(4));
    assert_eq!(obj.get("sub_blocks").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(obj.get("alignment").and_then(|v| v.as_u64()), Some(1));
    assert!(
        obj.contains_key("payload_hash"),
        "payload_hash MUST be present when Some"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. payload_hash omitted via skip_serializing_if when None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn payload_hash_omitted_from_wire_form_when_none() {
    let info = fixture_no_payload_hash();
    let value = serde_json::to_value(&info).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(
        !obj.contains_key("payload_hash"),
        "payload_hash MUST be omitted when None — got {value}"
    );
    // The other 5 fields are always present.
    assert!(obj.contains_key("transfer_length"));
    assert!(obj.contains_key("symbol_size"));
    assert!(obj.contains_key("source_blocks"));
    assert!(obj.contains_key("sub_blocks"));
    assert!(obj.contains_key("alignment"));
    assert_eq!(obj.len(), 5, "exactly 5 fields when payload_hash is None");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. payload_hash defaults to None via #[serde(default)]
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn payload_hash_defaults_to_none_when_missing_from_wire_form() {
    // The field has `#[serde(default, skip_serializing_if = "Option::is_none")]`
    // — pin that omitting it from the wire form yields None.
    let json = r#"{
        "transfer_length": 4096,
        "symbol_size": 512,
        "source_blocks": 8,
        "sub_blocks": 2,
        "alignment": 4
    }"#;
    let info: ConnectorBinaryTransmissionInfo = serde_json::from_str(json).expect("deserialize");
    assert_eq!(info.transfer_length, 4096);
    assert_eq!(info.symbol_size, 512);
    assert_eq!(info.source_blocks, 8);
    assert_eq!(info.sub_blocks, 2);
    assert_eq!(info.alignment, 4);
    assert_eq!(
        info.payload_hash, None,
        "payload_hash MUST default to None when omitted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. JSON round-trip preserves all fields
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_all_fields_when_payload_hash_some() {
    let original = fixture_with_payload_hash();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
}

#[test]
fn json_roundtrip_preserves_all_fields_when_payload_hash_none() {
    let original = fixture_no_payload_hash();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
    assert_eq!(back.payload_hash, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CBOR round-trip preserves all fields
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_all_fields_when_payload_hash_some() {
    let original = fixture_with_payload_hash();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: ConnectorBinaryTransmissionInfo =
        ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back, original);
}

#[test]
fn cbor_roundtrip_preserves_all_fields_when_payload_hash_none() {
    let original = fixture_no_payload_hash();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: ConnectorBinaryTransmissionInfo =
        ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back, original);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Boundary values per numeric field
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transfer_length_zero_round_trips() {
    let info = ConnectorBinaryTransmissionInfo::new(0, 256, 4, 1, 1);
    let json = serde_json::to_string(&info).unwrap();
    let back: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.transfer_length, 0);
}

#[test]
fn transfer_length_u64_max_round_trips() {
    let info = ConnectorBinaryTransmissionInfo::new(u64::MAX, 256, 4, 1, 1);

    // JSON
    let json = serde_json::to_string(&info).unwrap();
    let back_json: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back_json.transfer_length, u64::MAX);

    // CBOR
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&info, &mut buf).expect("CBOR encode");
    let back_cbor: ConnectorBinaryTransmissionInfo =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(back_cbor.transfer_length, u64::MAX);
}

#[test]
fn symbol_size_u16_max_round_trips() {
    let info = ConnectorBinaryTransmissionInfo::new(1024, u16::MAX, 4, u16::MAX, 1);
    let json = serde_json::to_string(&info).unwrap();
    let back: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.symbol_size, u16::MAX);
    assert_eq!(back.sub_blocks, u16::MAX);
}

#[test]
fn source_blocks_u8_max_round_trips() {
    let info = ConnectorBinaryTransmissionInfo::new(1024, 256, u8::MAX, 1, u8::MAX);
    let json = serde_json::to_string(&info).unwrap();
    let back: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.source_blocks, u8::MAX);
    assert_eq!(back.alignment, u8::MAX);
}

#[test]
fn all_zero_fields_round_trip() {
    let info = ConnectorBinaryTransmissionInfo::new(0, 0, 0, 0, 0);
    let json = serde_json::to_string(&info).unwrap();
    let back: ConnectorBinaryTransmissionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back, info);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. payload_hash JSON form is array of 32 numbers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn payload_hash_json_form_is_array_of_32_byte_values() {
    // [u8; 32] without `hex_or_bytes` serde adapter serializes as
    // a JSON array of 32 numbers. Pin that — it's distinct from
    // the hex-string form used by ObjectId/Signature elsewhere in
    // the codebase.
    let info = fixture_with_payload_hash();
    let value = serde_json::to_value(&info).expect("serialize");
    let hash_value = value.get("payload_hash").expect("payload_hash present");
    let arr = hash_value
        .as_array()
        .expect("payload_hash MUST be JSON array, not hex string");
    assert_eq!(arr.len(), 32, "payload_hash MUST be 32 bytes");
    // Verify the bytes match what we set (0..=31).
    for (i, v) in arr.iter().enumerate() {
        assert_eq!(v.as_u64(), Some(i as u64), "byte {i} mismatch: {v}");
    }
}

#[test]
fn payload_hash_distinct_from_hex_string_form() {
    // Pin loud: this field uses default serde serialization (JSON
    // array of u8), NOT the `hex_or_bytes` adapter that surfaces
    // [u8; 32] as a hex string elsewhere. Operators reading the
    // wire form MUST know to expect an array, not a string.
    let info = fixture_with_payload_hash();
    let json = serde_json::to_string(&info).unwrap();
    assert!(
        !json.contains("\"payload_hash\":\""),
        "payload_hash MUST NOT serialize as a hex string — got JSON {json}"
    );
    assert!(
        json.contains("\"payload_hash\":["),
        "payload_hash MUST serialize as a JSON array"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. CBOR payload_hash form
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_payload_hash_round_trips_byte_for_byte() {
    let mut hash = [0u8; 32];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = i as u8 ^ 0xAA;
    }
    let info = fixture_no_payload_hash().with_payload_hash(hash);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&info, &mut buf).expect("encode");
    let back: ConnectorBinaryTransmissionInfo =
        ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.payload_hash, Some(hash));
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_and_cbor_decode_to_same_value() {
    let original = fixture_with_payload_hash();

    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: ConnectorBinaryTransmissionInfo =
        serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("CBOR encode");
    let from_cbor: ConnectorBinaryTransmissionInfo =
        ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json, from_cbor);
    assert_eq!(from_json, original);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Nested usage in ConnectorBinarySymbolSet
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nested_in_connector_binary_symbol_set_preserved_through_json_roundtrip() {
    let symbol_set = ConnectorBinarySymbolSet {
        manifest_object_id: ObjectId::from_bytes([0x11; 32]),
        binary_object_id: ObjectId::from_bytes([0x22; 32]),
        target: ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        },
        binary_hash: "blake3-256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        encoded_body_hash:
            "blake3-256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
        oti: fixture_with_payload_hash(),
        source_symbols: 4,
        total_symbols: 6,
        mirrored_at: 1_700_000_000,
    };

    let json = serde_json::to_string(&symbol_set).expect("serialize");
    let back: ConnectorBinarySymbolSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.oti, symbol_set.oti);
    assert_eq!(back.oti.payload_hash, symbol_set.oti.payload_hash);
}

#[test]
fn nested_in_connector_binary_symbol_set_preserved_through_cbor_roundtrip() {
    let symbol_set = ConnectorBinarySymbolSet {
        manifest_object_id: ObjectId::from_bytes([0x33; 32]),
        binary_object_id: ObjectId::from_bytes([0x44; 32]),
        target: ConnectorTarget {
            os: "macos".to_string(),
            arch: "arm64".to_string(),
        },
        binary_hash: "blake3-256:3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
        encoded_body_hash:
            "blake3-256:4444444444444444444444444444444444444444444444444444444444444444"
                .to_string(),
        oti: fixture_no_payload_hash(),
        source_symbols: 8,
        total_symbols: 12,
        mirrored_at: 1_700_000_500,
    };

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&symbol_set, &mut buf).expect("encode");
    let back: ConnectorBinarySymbolSet = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.oti, symbol_set.oti);
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Distinct configurations produce distinct wire bytes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_transfer_lengths_produce_distinct_serialization() {
    let a = ConnectorBinaryTransmissionInfo::new(1024, 256, 4, 1, 1);
    let b = ConnectorBinaryTransmissionInfo::new(2048, 256, 4, 1, 1);
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn payload_hash_some_vs_none_produces_distinct_serialization() {
    let with_hash = fixture_with_payload_hash();
    let without_hash = fixture_no_payload_hash();
    assert_ne!(
        serde_json::to_string(&with_hash).unwrap(),
        serde_json::to_string(&without_hash).unwrap()
    );
}
