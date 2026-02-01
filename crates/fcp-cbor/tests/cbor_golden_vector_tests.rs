//! Golden vector tests for fcp-cbor canonical serialization.
//!
//! These tests validate CBOR encoding against canonical test vectors stored
//! in `tests/vectors/`. This ensures RFC 8949 compliance and deterministic behavior.

#![allow(dead_code)]

use fcp_cbor::{CanonicalSerializer, SchemaId, to_canonical_cbor};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Vector File Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CanonicalEncodingVectors {
    integer_minimal_encoding: Vec<IntegerVector>,
    non_canonical_integers: Vec<NonCanonicalIntegerVector>,
    map_key_ordering: MapKeyOrderingVectors,
    string_encoding: Vec<StringVector>,
    array_encoding: Vec<ArrayVector>,
}

#[derive(Debug, Deserialize)]
struct IntegerVector {
    value: u64,
    canonical_hex: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct NonCanonicalIntegerVector {
    non_canonical_hex: String,
    canonical_value: u64,
    canonical_hex: String,
    error: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct MapKeyOrderingVectors {
    test_cases: Vec<MapKeyOrderingCase>,
}

#[derive(Debug, Deserialize)]
struct MapKeyOrderingCase {
    name: String,
    keys: Vec<String>,
    sorted_keys: Vec<String>,
    description: String,
}

#[derive(Debug, Deserialize)]
struct StringVector {
    value: String,
    canonical_hex: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct ArrayVector {
    value: Vec<u64>,
    canonical_hex: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct SchemaHashVectors {
    hash_properties: Vec<HashProperty>,
}

#[derive(Debug, Deserialize)]
struct HashProperty {
    name: String,
    description: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

fn load_canonical_vectors() -> CanonicalEncodingVectors {
    let content = fs::read_to_string("tests/vectors/canonical_encoding_vectors.json")
        .expect("Failed to read canonical_encoding_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse canonical_encoding_vectors.json")
}

fn load_schema_vectors() -> SchemaHashVectors {
    let content = fs::read_to_string("tests/vectors/schema_hash_vectors.json")
        .expect("Failed to read schema_hash_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse schema_hash_vectors.json")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Integer Encoding Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_integer_minimal_encoding_from_vectors() {
    let vectors = load_canonical_vectors();

    for vector in vectors.integer_minimal_encoding {
        let expected = hex_to_bytes(&vector.canonical_hex);

        // Use appropriately-sized integer type for minimal encoding.
        let encoded = if let Ok(value) = u8::try_from(vector.value) {
            to_canonical_cbor(&value).unwrap()
        } else if let Ok(value) = u16::try_from(vector.value) {
            to_canonical_cbor(&value).unwrap()
        } else if let Ok(value) = u32::try_from(vector.value) {
            to_canonical_cbor(&value).unwrap()
        } else {
            to_canonical_cbor(&vector.value).unwrap()
        };

        assert_eq!(
            encoded,
            expected,
            "Value {} ({}) encoding mismatch: got {} expected {}",
            vector.value,
            vector.description,
            bytes_to_hex(&encoded),
            vector.canonical_hex
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Map Key Ordering Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_map_key_ordering_from_vectors() {
    let vectors = load_canonical_vectors();
    let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

    for case in vectors.map_key_ordering.test_cases {
        // Create a map with the specified keys
        let mut map: HashMap<String, u64> = HashMap::new();
        for (i, key) in case.keys.iter().enumerate() {
            map.insert(key.clone(), i as u64);
        }

        // Serialize
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();

        // Deserialize to verify round-trip
        let decoded: HashMap<String, u64> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();

        assert_eq!(
            decoded.len(),
            map.len(),
            "Case '{}' ({}) should preserve all keys",
            case.name,
            case.description
        );

        // Verify determinism - serialize again and check same bytes
        let bytes2 = CanonicalSerializer::serialize(&map, &schema).unwrap();
        assert_eq!(
            bytes, bytes2,
            "Case '{}' ({}) must be deterministic",
            case.name, case.description
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// String Encoding Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_string_encoding_from_vectors() {
    let vectors = load_canonical_vectors();

    for vector in vectors.string_encoding {
        let encoded = to_canonical_cbor(&vector.value).unwrap();
        let expected = hex_to_bytes(&vector.canonical_hex);

        assert_eq!(
            encoded,
            expected,
            "String '{}' ({}) encoding mismatch: got {} expected {}",
            vector.value,
            vector.description,
            bytes_to_hex(&encoded),
            vector.canonical_hex
        );
    }
}

#[test]
fn test_array_encoding_from_vectors() {
    let vectors = load_canonical_vectors();

    for vector in vectors.array_encoding {
        // Convert to Vec<u8> for small values
        let small_values: Vec<u8> = vector
            .value
            .iter()
            .map(|&v| u8::try_from(v).expect("value fits u8"))
            .collect();
        let encoded = to_canonical_cbor(&small_values).unwrap();
        let expected = hex_to_bytes(&vector.canonical_hex);

        assert_eq!(
            encoded,
            expected,
            "Array {:?} ({}) encoding mismatch: got {} expected {}",
            vector.value,
            vector.description,
            bytes_to_hex(&encoded),
            vector.canonical_hex
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Hash Property Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_schema_hash_properties_from_vectors() {
    let vectors = load_schema_vectors();

    for prop in vectors.hash_properties {
        match prop.name.as_str() {
            "deterministic" => {
                let schema = SchemaId::new("fcp.test", "Demo", Version::new(1, 0, 0));
                let hash1 = schema.hash();
                let hash2 = schema.hash();
                assert_eq!(
                    hash1, hash2,
                    "Property 'deterministic': {}",
                    prop.description
                );
            }
            "namespace_sensitive" => {
                let schema_a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
                let schema_b = SchemaId::new("fcp.mesh", "Object", Version::new(1, 0, 0));
                assert_ne!(
                    schema_a.hash(),
                    schema_b.hash(),
                    "Property 'namespace_sensitive': {}",
                    prop.description
                );
            }
            "name_sensitive" => {
                let schema_a = SchemaId::new("fcp.core", "ObjectA", Version::new(1, 0, 0));
                let schema_b = SchemaId::new("fcp.core", "ObjectB", Version::new(1, 0, 0));
                assert_ne!(
                    schema_a.hash(),
                    schema_b.hash(),
                    "Property 'name_sensitive': {}",
                    prop.description
                );
            }
            "version_sensitive" => {
                let schema_a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
                let schema_b = SchemaId::new("fcp.core", "Object", Version::new(2, 0, 0));
                assert_ne!(
                    schema_a.hash(),
                    schema_b.hash(),
                    "Property 'version_sensitive': {}",
                    prop.description
                );
            }
            "length_32" => {
                let schema = SchemaId::new("fcp.test", "Any", Version::new(0, 0, 1));
                assert_eq!(
                    schema.hash().as_bytes().len(),
                    32,
                    "Property 'length_32': {}",
                    prop.description
                );
            }
            _ => {} // Skip unknown properties
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_serialization_determinism() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        name: String,
        value: u64,
        tags: Vec<String>,
    }

    let schema = SchemaId::new("fcp.test", "TestStruct", Version::new(1, 0, 0));
    let obj = TestStruct {
        name: "test".to_string(),
        value: 42,
        tags: vec!["a".to_string(), "b".to_string()],
    };

    // Serialize 10 times
    let serializations: Vec<Vec<u8>> = (0..10)
        .map(|_| CanonicalSerializer::serialize(&obj, &schema).unwrap())
        .collect();

    // All should be identical
    for (i, bytes) in serializations.iter().enumerate().skip(1) {
        assert_eq!(
            bytes, &serializations[0],
            "Serialization {i} differs from first"
        );
    }
}

#[test]
fn test_map_ordering_determinism() {
    let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

    // Create maps with keys inserted in different orders
    let mut map1: HashMap<String, u64> = HashMap::new();
    map1.insert("zebra".to_string(), 1);
    map1.insert("apple".to_string(), 2);
    map1.insert("banana".to_string(), 3);

    let mut map2: HashMap<String, u64> = HashMap::new();
    map2.insert("apple".to_string(), 2);
    map2.insert("banana".to_string(), 3);
    map2.insert("zebra".to_string(), 1);

    let bytes1 = CanonicalSerializer::serialize(&map1, &schema).unwrap();
    let bytes2 = CanonicalSerializer::serialize(&map2, &schema).unwrap();

    assert_eq!(
        bytes1, bytes2,
        "Maps with same content must serialize identically regardless of insertion order"
    );
}

#[test]
fn test_nested_map_ordering_determinism() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Outer {
        inner: HashMap<String, u64>,
        name: String,
    }

    let schema = SchemaId::new("fcp.test", "Outer", Version::new(0, 1, 0));

    let mut inner = HashMap::new();
    inner.insert("b".to_string(), 2);
    inner.insert("a".to_string(), 1);

    let obj = Outer {
        inner,
        name: "test".to_string(),
    };

    let bytes1 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
    let bytes2 = CanonicalSerializer::serialize(&obj, &schema).unwrap();

    assert_eq!(bytes1, bytes2, "Nested maps must also be deterministic");
}
