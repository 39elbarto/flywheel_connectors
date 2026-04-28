use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use fcp_core::{ConnectorId, ConnectorTarget, ManifestVersion, ObjectId, RegistryEntry};
use semver::Version;

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn object_id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn registry_entry(
    connector_id: ConnectorId,
    version: ManifestVersion,
    os: &str,
    arch: &str,
    manifest_byte: u8,
    binary_byte: u8,
) -> RegistryEntry {
    RegistryEntry::new(
        connector_id,
        version,
        ConnectorTarget {
            os: os.to_string(),
            arch: arch.to_string(),
        },
        object_id(manifest_byte),
        object_id(binary_byte),
    )
}

fn base_entry() -> RegistryEntry {
    registry_entry(
        ConnectorId::from_static("github:request-response:v1"),
        ManifestVersion::from(Version::new(1, 2, 3)),
        "linux",
        "amd64",
        0x11,
        0x22,
    )
}

#[test]
fn same_registry_entry_literals_are_equal_and_hash_identically() {
    let left = base_entry();
    let right = base_entry();

    assert_eq!(left, right);
    assert_eq!(hash_value(&left), hash_value(&right));
}

#[test]
fn registry_entry_equality_covers_identity_version_target_and_objects() {
    let base = base_entry();
    let variants = [
        registry_entry(
            ConnectorId::from_static("gitlab:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 3)),
            "linux",
            "amd64",
            0x11,
            0x22,
        ),
        registry_entry(
            ConnectorId::from_static("github:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 4)),
            "linux",
            "amd64",
            0x11,
            0x22,
        ),
        registry_entry(
            ConnectorId::from_static("github:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 3)),
            "darwin",
            "amd64",
            0x11,
            0x22,
        ),
        registry_entry(
            ConnectorId::from_static("github:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 3)),
            "linux",
            "arm64",
            0x11,
            0x22,
        ),
        registry_entry(
            ConnectorId::from_static("github:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 3)),
            "linux",
            "amd64",
            0x33,
            0x22,
        ),
        registry_entry(
            ConnectorId::from_static("github:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 3)),
            "linux",
            "amd64",
            0x11,
            0x44,
        ),
    ];

    for variant in variants {
        assert_ne!(base, variant);
        assert_ne!(hash_value(&base), hash_value(&variant));
    }
}

#[test]
fn registry_entry_hash_collections_deduplicate_equal_entries() {
    let base = base_entry();
    let mut set = HashSet::new();

    assert!(set.insert(base.clone()));
    assert!(!set.insert(base_entry()));
    assert!(set.insert(registry_entry(
        ConnectorId::from_static("github:request-response:v1"),
        ManifestVersion::from(Version::new(1, 2, 3)),
        "linux",
        "arm64",
        0x11,
        0x22,
    )));

    assert_eq!(set.len(), 2);
    assert!(set.contains(&base));
}

#[test]
fn registry_entry_hashmap_lookup_survives_reconstruction() {
    let base = base_entry();
    let mut map = HashMap::new();
    map.insert(base.clone(), "mirrored");

    assert_eq!(map.get(&base_entry()), Some(&"mirrored"));
    assert_eq!(
        map.get(&registry_entry(
            ConnectorId::from_static("github:request-response:v1"),
            ManifestVersion::from(Version::new(1, 2, 3)),
            "linux",
            "arm64",
            0x11,
            0x22,
        )),
        None
    );
}

#[test]
fn registry_entry_symbol_set_object_id_participates_in_equality_and_hash() {
    let without_symbols = base_entry();
    let with_symbols = base_entry().with_symbol_set_object_id(object_id(0x55));

    assert_ne!(without_symbols, with_symbols);
    assert_ne!(hash_value(&without_symbols), hash_value(&with_symbols));

    let mut set = HashSet::new();
    set.insert(without_symbols.clone());
    set.insert(with_symbols.clone());

    assert_eq!(set.len(), 2);
    assert!(set.contains(&without_symbols));
    assert!(set.contains(&with_symbols));
}
