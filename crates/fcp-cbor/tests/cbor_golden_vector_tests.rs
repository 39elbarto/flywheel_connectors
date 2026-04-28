//! Golden vector tests for fcp-cbor canonical serialization.
//!
//! These tests validate CBOR encoding against canonical test vectors stored
//! in `tests/vectors/`. This ensures RFC 8949 compliance and deterministic behavior.

#![allow(dead_code)]

use fcp_cbor::{to_canonical_cbor, CanonicalSerializer, SchemaId};
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
    negative_integer_minimal_encoding: Vec<NegativeIntegerVector>,
    simple_value_encoding: Vec<SimpleValueVector>,
    non_canonical_integers: Vec<NonCanonicalIntegerVector>,
    map_key_ordering: MapKeyOrderingVectors,
    string_encoding: Vec<StringVector>,
    array_encoding: Vec<ArrayVector>,
}

#[derive(Debug, Deserialize)]
struct NegativeIntegerVector {
    value: i64,
    canonical_hex: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct SimpleValueVector {
    value_name: String,
    canonical_hex: String,
    description: String,
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
    canonical_hex: String,
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

fn assert_positive_integer_shortest_form(value: u64, expected_hex: &str) {
    let encoded = to_canonical_cbor(&value).unwrap();
    let expected = hex_to_bytes(expected_hex);

    assert_eq!(
        encoded,
        expected,
        "positive integer {value} did not use the expected shortest-form CBOR bytes: got {} expected {expected_hex}",
        bytes_to_hex(&encoded)
    );

    let decoded: u64 = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(
        decoded, value,
        "positive integer {value} did not roundtrip from shortest-form CBOR"
    );
}

fn assert_negative_integer_shortest_form(value: i64, expected_hex: &str) {
    let encoded = to_canonical_cbor(&value).unwrap();
    let expected = hex_to_bytes(expected_hex);

    assert_eq!(
        encoded,
        expected,
        "negative integer {value} did not use the expected shortest-form CBOR bytes: got {} expected {expected_hex}",
        bytes_to_hex(&encoded)
    );

    let decoded: i64 = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(
        decoded, value,
        "negative integer {value} did not roundtrip from shortest-form CBOR"
    );
}

fn assert_array_length_prefix_shortest_form(len: usize, expected_prefix_hex: &str) {
    let value = vec![0_u8; len];
    let encoded = to_canonical_cbor(&value).unwrap();
    let expected_prefix = hex_to_bytes(expected_prefix_hex);

    assert_eq!(
        &encoded[..expected_prefix.len()],
        expected_prefix.as_slice(),
        "array length {len} did not use the expected shortest-form length prefix: got {} expected {expected_prefix_hex}",
        bytes_to_hex(&encoded[..expected_prefix.len()])
    );

    let decoded: Vec<u8> = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    assert_eq!(
        decoded, value,
        "array length {len} did not roundtrip from shortest-form CBOR"
    );
}

macro_rules! positive_integer_shortest_form_boundary {
    ($test_name:ident, $value:expr, $expected_hex:literal) => {
        #[test]
        fn $test_name() {
            assert_positive_integer_shortest_form($value, $expected_hex);
        }
    };
}

macro_rules! negative_integer_shortest_form_boundary {
    ($test_name:ident, $value:expr, $expected_hex:literal) => {
        #[test]
        fn $test_name() {
            assert_negative_integer_shortest_form($value, $expected_hex);
        }
    };
}

macro_rules! array_length_prefix_boundary {
    ($test_name:ident, $len:expr, $expected_prefix_hex:literal) => {
        #[test]
        fn $test_name() {
            assert_array_length_prefix_shortest_form($len, $expected_prefix_hex);
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Integer Encoding Tests
// ─────────────────────────────────────────────────────────────────────────────

positive_integer_shortest_form_boundary!(positive_integer_shortest_form_0, 0, "00");
positive_integer_shortest_form_boundary!(positive_integer_shortest_form_23, 23, "17");
positive_integer_shortest_form_boundary!(positive_integer_shortest_form_24, 24, "1818");
positive_integer_shortest_form_boundary!(positive_integer_shortest_form_255, 255, "18ff");
positive_integer_shortest_form_boundary!(positive_integer_shortest_form_256, 256, "190100");
positive_integer_shortest_form_boundary!(positive_integer_shortest_form_65535, 65_535, "19ffff");
positive_integer_shortest_form_boundary!(
    positive_integer_shortest_form_65536,
    65_536,
    "1a00010000"
);
positive_integer_shortest_form_boundary!(
    positive_integer_shortest_form_u32_max,
    4_294_967_295,
    "1affffffff"
);
positive_integer_shortest_form_boundary!(
    positive_integer_shortest_form_u32_max_plus_one,
    4_294_967_296,
    "1b0000000100000000"
);
positive_integer_shortest_form_boundary!(
    positive_integer_shortest_form_u64_max,
    u64::MAX,
    "1bffffffffffffffff"
);

negative_integer_shortest_form_boundary!(negative_integer_shortest_form_minus_1, -1, "20");
negative_integer_shortest_form_boundary!(negative_integer_shortest_form_minus_24, -24, "37");
negative_integer_shortest_form_boundary!(negative_integer_shortest_form_minus_25, -25, "3818");
negative_integer_shortest_form_boundary!(negative_integer_shortest_form_minus_256, -256, "38ff");
negative_integer_shortest_form_boundary!(negative_integer_shortest_form_minus_257, -257, "390100");
negative_integer_shortest_form_boundary!(
    negative_integer_shortest_form_minus_65536,
    -65_536,
    "39ffff"
);
negative_integer_shortest_form_boundary!(
    negative_integer_shortest_form_i64_min,
    i64::MIN,
    "3b7fffffffffffffff"
);

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
// Negative Integer Encoding Tests (RFC 8949 §3.1, major type 1)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_negative_integer_minimal_encoding_from_vectors() {
    let vectors = load_canonical_vectors();

    for vector in vectors.negative_integer_minimal_encoding {
        let expected = hex_to_bytes(&vector.canonical_hex);

        // Choose the smallest signed type that can hold the value, mirroring
        // how the positive-integer test selects an unsigned type. Encoding
        // must be type-width-independent (RFC 8949 §3.1: minor 0..27 alone
        // dictates byte count), so this also exercises the canonicalizer's
        // narrow-width handling.
        let encoded = if let Ok(value) = i8::try_from(vector.value) {
            to_canonical_cbor(&value).unwrap()
        } else if let Ok(value) = i16::try_from(vector.value) {
            to_canonical_cbor(&value).unwrap()
        } else if let Ok(value) = i32::try_from(vector.value) {
            to_canonical_cbor(&value).unwrap()
        } else {
            to_canonical_cbor(&vector.value).unwrap()
        };

        assert_eq!(
            encoded,
            expected,
            "Negative value {} ({}) encoding mismatch: got {} expected {}",
            vector.value,
            vector.description,
            bytes_to_hex(&encoded),
            vector.canonical_hex
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple Value Encoding Tests (RFC 8949 §3.3, major type 7)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_simple_value_encoding_from_vectors() -> Result<(), String> {
    let vectors = load_canonical_vectors();

    for vector in vectors.simple_value_encoding {
        let expected = hex_to_bytes(&vector.canonical_hex);

        let encoded = match vector.value_name.as_str() {
            "false" => to_canonical_cbor(&false).unwrap(),
            "true" => to_canonical_cbor(&true).unwrap(),
            // serde represents `null` as `Option::None`; ciborium emits
            // major type 7 / minor 22 (0xf6) for it.
            "null" => to_canonical_cbor(&Option::<u8>::None).unwrap(),
            other => return Err(format!("unknown simple value '{other}' in golden vectors")),
        };

        assert_eq!(
            encoded,
            expected,
            "Simple value '{}' ({}) encoding mismatch: got {} expected {}",
            vector.value_name,
            vector.description,
            bytes_to_hex(&encoded),
            vector.canonical_hex
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Map Key Ordering Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_map_key_ordering_from_vectors() {
    let vectors = load_canonical_vectors();

    for case in vectors.map_key_ordering.test_cases {
        // Create a map with the specified keys
        let mut map: HashMap<String, u64> = HashMap::new();
        for (i, key) in case.keys.iter().enumerate() {
            map.insert(key.clone(), i as u64);
        }

        let bytes = to_canonical_cbor(&map).unwrap();
        let expected = hex_to_bytes(&case.canonical_hex);

        assert_eq!(
            bytes,
            expected,
            "Case '{}' ({}) canonical map encoding mismatch for sorted key order {:?}: got {} expected {}",
            case.name,
            case.description,
            case.sorted_keys,
            bytes_to_hex(&bytes),
            case.canonical_hex
        );
    }
}

#[test]
fn test_integer_shortest_encoding_is_type_width_independent() {
    let cases = [
        ("24_u8", to_canonical_cbor(&24_u8).unwrap(), "1818"),
        ("24_u16", to_canonical_cbor(&24_u16).unwrap(), "1818"),
        ("24_u32", to_canonical_cbor(&24_u32).unwrap(), "1818"),
        ("24_u64", to_canonical_cbor(&24_u64).unwrap(), "1818"),
        (
            "2^32_u64",
            to_canonical_cbor(&4_294_967_296_u64).unwrap(),
            "1b0000000100000000",
        ),
        (
            "u64::MAX",
            to_canonical_cbor(&u64::MAX).unwrap(),
            "1bffffffffffffffff",
        ),
        ("-25_i8", to_canonical_cbor(&(-25_i8)).unwrap(), "3818"),
        ("-25_i16", to_canonical_cbor(&(-25_i16)).unwrap(), "3818"),
        ("-25_i32", to_canonical_cbor(&(-25_i32)).unwrap(), "3818"),
        ("-25_i64", to_canonical_cbor(&(-25_i64)).unwrap(), "3818"),
        (
            "-(2^32 + 1)_i64",
            to_canonical_cbor(&(-4_294_967_297_i64)).unwrap(),
            "3b0000000100000000",
        ),
        (
            "i64::MIN",
            to_canonical_cbor(&i64::MIN).unwrap(),
            "3b7fffffffffffffff",
        ),
    ];

    for (name, encoded, expected_hex) in cases {
        assert_eq!(
            encoded,
            hex_to_bytes(expected_hex),
            "{name} did not use the shortest canonical CBOR form"
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

array_length_prefix_boundary!(array_length_prefix_shortest_form_0, 0, "80");
array_length_prefix_boundary!(array_length_prefix_shortest_form_23, 23, "97");
array_length_prefix_boundary!(array_length_prefix_shortest_form_24, 24, "9818");
array_length_prefix_boundary!(array_length_prefix_shortest_form_255, 255, "98ff");
array_length_prefix_boundary!(array_length_prefix_shortest_form_256, 256, "990100");
array_length_prefix_boundary!(array_length_prefix_shortest_form_65535, 65_535, "99ffff");
array_length_prefix_boundary!(
    array_length_prefix_shortest_form_65536,
    65_536,
    "9a00010000"
);

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
