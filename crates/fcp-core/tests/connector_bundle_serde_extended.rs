//! Extended pinning for `ConnectorBundle` + `RegistryEntry`
//! Display + serde shape (flywheel_connectors-huv65).
//!
//! The basic surface (Display format, JSON+CBOR round-trip on a
//! single fixture) is covered by `connector_bundle_display_serde.rs`.
//! This test pins the ADDITIONAL invariants the bead's
//! "Display formatting + serde JSON+CBOR roundtrip" contract relies
//! on but the basic surface doesn't enumerate:
//!
//!   1. **Display format generalizes across os/arch combos** — the
//!      target prefix follows `<os>-<arch>` exactly for several
//!      documented platforms.
//!   2. **Display byte-count fields match actual `.len()`** for
//!      various input sizes.
//!   3. **Empty manifest_toml / empty binary** still produce a
//!      well-formed Display string.
//!   4. **Multi-byte UTF-8 manifest_toml** preserved through both
//!      JSON and CBOR.
//!   5. **Distinct bundles produce distinct JSON bytes** — bundle
//!      content is part of the wire identity.
//!   6. **`RegistryEntry` JSON shape pinned** (the paired type that
//!      indexes ConnectorBundle artifacts in the registry).
//!   7. **`RegistryEntry.symbol_set_object_id` Some-vs-None semantics**
//!      via `skip_serializing_if = "Option::is_none"`.
//!   8. **`RegistryEntry` round-trip** through JSON + CBOR.
//!   9. **`RegistryEntry` Hash + Eq correctness** for HashMap-key
//!      usage (it derives Hash + Eq).

use fcp_cbor::SchemaId;
use fcp_core::{
    ConnectorBundle, ConnectorId, ConnectorTarget, ConnectorVersion, ObjectId, RegistryEntry,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn target(os: &str, arch: &str) -> ConnectorTarget {
    ConnectorTarget {
        os: os.to_string(),
        arch: arch.to_string(),
    }
}

fn hash_of<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// Ensure SchemaId import is used (silences unused-import warnings
// when wiring up future fixtures); referenced lightly.
#[allow(dead_code)]
fn _schema_marker() -> SchemaId {
    SchemaId::new("fcp.core", "marker", semver::Version::new(1, 0, 0))
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Display format generalizes across os/arch combos
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_format_generalizes_across_os_arch_combos() {
    let cases = [
        (target("linux", "amd64"), "linux-amd64"),
        (target("macos", "arm64"), "macos-arm64"),
        (target("windows", "amd64"), "windows-amd64"),
        (target("freebsd", "x86_64"), "freebsd-x86_64"),
    ];
    for (target, expected_prefix) in cases {
        let bundle = ConnectorBundle::new("[m]\n", vec![0u8; 8], target);
        let displayed = bundle.to_string();
        assert!(
            displayed.starts_with(expected_prefix),
            "Display MUST start with `<os>-<arch>` ({expected_prefix:?}); got {displayed}"
        );
        assert!(
            displayed.contains("connector bundle"),
            "Display MUST contain literal `connector bundle`; got {displayed}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Display byte-count fields match actual lengths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_byte_counts_match_actual_lengths_for_various_sizes() {
    let manifest = "version=\"1.0.0\"\nname=\"x\"\n"; // 24 bytes
    let cases: [(&str, Vec<u8>, usize, usize); 4] = [
        (manifest, vec![], manifest.len(), 0),
        (manifest, vec![0u8; 1], manifest.len(), 1),
        (manifest, vec![0u8; 1024], manifest.len(), 1024),
        (manifest, vec![0u8; 65_536], manifest.len(), 65_536),
    ];
    for (m, b, m_expected, b_expected) in cases {
        let bundle = ConnectorBundle::new(m, b, target("linux", "amd64"));
        let displayed = bundle.to_string();
        let expected = format!(
            "linux-amd64 connector bundle (manifest_toml={m_expected} bytes, binary={b_expected} bytes)"
        );
        assert_eq!(
            displayed, expected,
            "Display byte counts MUST match actual lengths"
        );
    }
}

#[test]
fn empty_manifest_and_binary_still_produce_well_formed_display() {
    let bundle = ConnectorBundle::new("", Vec::<u8>::new(), target("linux", "amd64"));
    assert_eq!(
        bundle.to_string(),
        "linux-amd64 connector bundle (manifest_toml=0 bytes, binary=0 bytes)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Multi-byte UTF-8 manifest preserved
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn multibyte_utf8_manifest_round_trips_through_json_and_cbor() {
    // 日本語 + emoji to exercise multi-byte UTF-8 paths.
    let manifest = "name = \"日本語\"\ndescription = \"connector ✨\"\n";
    let original = ConnectorBundle::new(
        manifest,
        vec![0xCA, 0xFE, 0xBA, 0xBE],
        target("macos", "arm64"),
    );

    // JSON
    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: ConnectorBundle = serde_json::from_str(&json).expect("JSON deserialize");
    assert_eq!(from_json, original);
    assert_eq!(from_json.manifest_toml, manifest);

    // CBOR
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("CBOR encode");
    let from_cbor: ConnectorBundle =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(from_cbor, original);
    assert_eq!(from_cbor.manifest_toml, manifest);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Distinct bundles produce distinct JSON bytes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_manifest_produces_distinct_serialization() {
    let a = ConnectorBundle::new("name = \"a\"", vec![0u8; 4], target("linux", "amd64"));
    let b = ConnectorBundle::new("name = \"b\"", vec![0u8; 4], target("linux", "amd64"));
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_binary_produces_distinct_serialization() {
    let a = ConnectorBundle::new("m", vec![0xAA; 8], target("linux", "amd64"));
    let b = ConnectorBundle::new("m", vec![0xBB; 8], target("linux", "amd64"));
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_target_produces_distinct_serialization() {
    let a = ConnectorBundle::new("m", vec![0u8; 4], target("linux", "amd64"));
    let b = ConnectorBundle::new("m", vec![0u8; 4], target("macos", "arm64"));
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. RegistryEntry JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_entry_json_shape_pinned_with_optional_symbol_set_omitted() {
    let entry = RegistryEntry::new(
        ConnectorId::from_static("connector:fcp.test"),
        ConnectorVersion::parse("1.2.3").expect("version"),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x11; 32]),
        ObjectId::from_bytes([0x22; 32]),
    );

    let value = serde_json::to_value(&entry).expect("serialize");
    let obj = value.as_object().expect("RegistryEntry is JSON object");
    assert!(
        !obj.contains_key("symbol_set_object_id"),
        "symbol_set_object_id MUST be omitted when None"
    );
    assert_eq!(
        obj.get("connector_id").and_then(|v| v.as_str()),
        Some("connector:fcp.test")
    );
    assert_eq!(obj.get("version").and_then(|v| v.as_str()), Some("1.2.3"));
    let inner_target = obj
        .get("target")
        .and_then(|v| v.as_object())
        .expect("target");
    assert_eq!(
        inner_target.get("os").and_then(|v| v.as_str()),
        Some("linux")
    );
    assert_eq!(
        inner_target.get("arch").and_then(|v| v.as_str()),
        Some("amd64")
    );
}

#[test]
fn registry_entry_json_shape_pinned_with_symbol_set_present() {
    let entry = RegistryEntry::new(
        ConnectorId::from_static("connector:fcp.test"),
        ConnectorVersion::parse("1.2.3").expect("version"),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x11; 32]),
        ObjectId::from_bytes([0x22; 32]),
    )
    .with_symbol_set_object_id(ObjectId::from_bytes([0x33; 32]));

    let value = serde_json::to_value(&entry).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(
        obj.contains_key("symbol_set_object_id"),
        "symbol_set_object_id MUST be present when Some"
    );
    let sym = obj
        .get("symbol_set_object_id")
        .and_then(|v| v.as_str())
        .expect("symbol_set_object_id is string");
    assert_eq!(sym, "33".repeat(32), "ObjectId hex form pinned");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. RegistryEntry round-trip through JSON + CBOR
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_entry_json_roundtrip_preserves_fields() {
    let entry = RegistryEntry::new(
        ConnectorId::from_static("connector:fcp.test"),
        ConnectorVersion::parse("2.0.0").expect("version"),
        target("macos", "arm64"),
        ObjectId::from_bytes([0xAA; 32]),
        ObjectId::from_bytes([0xBB; 32]),
    )
    .with_symbol_set_object_id(ObjectId::from_bytes([0xCC; 32]));

    let json = serde_json::to_string(&entry).expect("serialize");
    let back: RegistryEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, entry);
    assert_eq!(back.symbol_set_object_id, entry.symbol_set_object_id);
}

#[test]
fn registry_entry_cbor_roundtrip_preserves_fields() {
    let entry = RegistryEntry::new(
        ConnectorId::from_static("connector:fcp.test"),
        ConnectorVersion::parse("1.0.0").expect("version"),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x01; 32]),
        ObjectId::from_bytes([0x02; 32]),
    );

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&entry, &mut buf).expect("CBOR encode");
    let back: RegistryEntry = ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(back, entry);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. RegistryEntry Hash + Eq correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equal_registry_entries_hash_equally() {
    let a = RegistryEntry::new(
        ConnectorId::from_static("c"),
        ConnectorVersion::parse("1.0.0").unwrap(),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x42; 32]),
        ObjectId::from_bytes([0x43; 32]),
    );
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn distinct_registry_entries_hash_distinctly_in_practice() {
    let base = RegistryEntry::new(
        ConnectorId::from_static("c"),
        ConnectorVersion::parse("1.0.0").unwrap(),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x42; 32]),
        ObjectId::from_bytes([0x43; 32]),
    );

    // Distinguishing on each field axis.
    let diff_version = RegistryEntry::new(
        ConnectorId::from_static("c"),
        ConnectorVersion::parse("1.0.1").unwrap(),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x42; 32]),
        ObjectId::from_bytes([0x43; 32]),
    );
    assert_ne!(base, diff_version);
    assert_ne!(hash_of(&base), hash_of(&diff_version));

    let diff_target = RegistryEntry::new(
        ConnectorId::from_static("c"),
        ConnectorVersion::parse("1.0.0").unwrap(),
        target("macos", "arm64"),
        ObjectId::from_bytes([0x42; 32]),
        ObjectId::from_bytes([0x43; 32]),
    );
    assert_ne!(base, diff_target);
    assert_ne!(hash_of(&base), hash_of(&diff_target));

    let with_sym = base
        .clone()
        .with_symbol_set_object_id(ObjectId::from_bytes([0x77; 32]));
    assert_ne!(base, with_sym);
    assert_ne!(hash_of(&base), hash_of(&with_sym));
}

#[test]
fn registry_entry_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<RegistryEntry, &'static str> = HashMap::new();
    let entry = RegistryEntry::new(
        ConnectorId::from_static("c"),
        ConnectorVersion::parse("1.0.0").unwrap(),
        target("linux", "amd64"),
        ObjectId::from_bytes([0x42; 32]),
        ObjectId::from_bytes([0x43; 32]),
    );
    map.insert(entry.clone(), "seen");
    assert_eq!(map.get(&entry), Some(&"seen"));
}
