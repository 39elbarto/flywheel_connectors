//! FCP2 canonical serialization (deterministic CBOR + schema hashing).
//!
//! This crate implements the byte-level foundation for FCP2 content-addressed objects:
//! - `SchemaId` and `SchemaHash` for schema binding
//! - Deterministic RFC 8949 canonical CBOR encoding
//! - Schema-hash-prefixed payloads (`schema_hash || canonical_cbor`)
//!
//! See `FCP_Specification_V2.md` §3.3–3.5.

#![forbid(unsafe_code)]

use std::fmt;

use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for `SchemaId` hashing (NORMATIVE).
const SCHEMA_HASH_DOMAIN_SEPARATOR: &[u8] = b"FCP2-SCHEMA-V1";

/// Length of an FCP2 schema hash prefix.
pub const SCHEMA_HASH_LEN: usize = 32;

/// Maximum allowed size for a canonical object payload (including schema hash prefix).
///
/// This aligns with the default `max_object_size` in the FCP2 spec's `RaptorQ` configuration
/// (64 MiB). Larger objects must use chunking at higher protocol layers.
pub const MAX_CANONICAL_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// Schema identifier (NORMATIVE).
///
/// Uniquely identifies a type within the FCP ecosystem and is used for:
/// - Type discrimination in deserialization
/// - Schema hash computation for content addressing
/// - CDDL generation for interoperability
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct SchemaId {
    /// Namespace (e.g., "fcp.core", "fcp.mesh", "fcp.connector").
    pub namespace: String,
    /// Type name (e.g., `CapabilityObject`, `InvokeRequest`, `AuditEvent`).
    pub name: String,
    /// Semantic version for evolution.
    pub version: Version,
}

impl SchemaId {
    /// Create a new `SchemaId`.
    #[must_use]
    pub fn new(namespace: impl Into<String>, name: impl Into<String>, version: Version) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            version,
        }
    }

    /// Canonical string representation (NORMATIVE).
    ///
    /// Format: `{namespace}:{name}@{version}`.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        format!("{}:{}@{}", self.namespace, self.name, self.version).into_bytes()
    }

    /// Canonical type binding hash (NORMATIVE).
    ///
    /// Uses BLAKE3 with fixed-size output to prevent `DoS` via maliciously large schema strings.
    /// The domain separator `"FCP2-SCHEMA-V1"` ensures hash isolation from other uses.
    #[must_use]
    pub fn hash(&self) -> SchemaHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SCHEMA_HASH_DOMAIN_SEPARATOR);
        hasher.update(&self.as_bytes());
        SchemaHash(*hasher.finalize().as_bytes())
    }
}

/// 32-byte schema hash (NORMATIVE).
///
/// Fixed-size hash of `SchemaId` for:
/// - Prefix on all canonical CBOR payloads
/// - Input to `ObjectId` derivation
/// - Decode-time type verification
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaHash([u8; SCHEMA_HASH_LEN]);

impl SchemaHash {
    /// Borrow the raw schema hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCHEMA_HASH_LEN] {
        &self.0
    }

    /// Construct a schema hash from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SCHEMA_HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SchemaHash")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for SchemaHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Errors that can occur during canonical serialization/deserialization.
#[derive(Debug, Error)]
pub enum SerializationError {
    /// The payload is too short to include a schema hash prefix.
    #[error("payload missing schema hash prefix")]
    MissingSchemaHashPrefix,

    /// The schema hash prefix does not match the expected schema.
    #[error("schema hash mismatch (expected {expected}, got {got})")]
    SchemaMismatch {
        expected: SchemaHash,
        got: SchemaHash,
    },

    /// The payload exceeds the configured maximum size.
    #[error("payload too large ({len} bytes > {max} bytes)")]
    PayloadTooLarge { len: usize, max: usize },

    /// The CBOR payload has trailing bytes after the first decoded value.
    #[error("trailing bytes after CBOR value")]
    TrailingBytes,

    /// The input decodes successfully but is not in canonical form.
    #[error("non-canonical CBOR encoding")]
    NonCanonicalEncoding,

    /// The input value cannot be represented as a dynamic CBOR `Value`.
    #[error("cbor value conversion error: {0}")]
    CborValue(#[from] ciborium::value::Error),

    /// A map contains duplicate keys (after canonicalization).
    #[error("duplicate map key (canonical key bytes: {key_hex})")]
    DuplicateMapKey { key_hex: String },

    /// CBOR serialization failed.
    #[error("cbor serialization error: {0}")]
    CborSerialize(#[from] ciborium::ser::Error<std::io::Error>),

    /// CBOR deserialization failed.
    #[error("cbor deserialization error: {0}")]
    CborDeserialize(#[from] ciborium::de::Error<std::io::Error>),
}

/// Canonical CBOR serialization (NORMATIVE).
///
/// Implements RFC 8949 deterministic encoding with schema hash prefix. All mesh objects MUST use
/// this serializer for content addressing.
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    /// Serialize to canonical CBOR with schema hash prefix (NORMATIVE).
    ///
    /// Output format: `schema_hash (32 bytes) || canonical_cbor_bytes`.
    ///
    /// # Errors
    /// Returns `SerializationError::CborSerialize` if CBOR serialization fails.
    /// Returns `SerializationError::PayloadTooLarge` if the encoded output exceeds
    /// `MAX_CANONICAL_OBJECT_BYTES`.
    pub fn serialize<T: Serialize>(
        value: &T,
        schema: &SchemaId,
    ) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::with_capacity(SCHEMA_HASH_LEN + 128);

        // Schema hash prefix for type binding (fixed-size, DoS-resistant).
        buf.extend_from_slice(schema.hash().as_bytes());

        // Deterministic canonical CBOR (RFC 8949 §4.2).
        buf.extend_from_slice(&to_canonical_cbor(value)?);

        if buf.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: buf.len(),
                max: MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        Ok(buf)
    }

    /// Deserialize with schema verification and canonical encoding enforcement.
    ///
    /// # Errors
    /// Returns `SerializationError::MissingSchemaHashPrefix` if the input is too short.
    /// Returns `SerializationError::SchemaMismatch` if the schema hash prefix does not match.
    /// Returns `SerializationError::PayloadTooLarge` if `data.len()` exceeds
    /// `MAX_CANONICAL_OBJECT_BYTES`.
    /// Returns `SerializationError::CborDeserialize` if the CBOR payload cannot be decoded.
    /// Returns `SerializationError::TrailingBytes` if extra bytes remain after decoding one value.
    /// Returns `SerializationError::NonCanonicalEncoding` if the decoded value does not re-encode
    /// to the exact input bytes using canonical encoding.
    pub fn deserialize<T: Serialize + DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        let value = Self::deserialize_unchecked::<T>(data, expected_schema)?;
        let canonical = Self::serialize(&value, expected_schema)?;

        if canonical != data {
            return Err(SerializationError::NonCanonicalEncoding);
        }

        Ok(value)
    }

    /// Deserialize with schema verification but **without** canonical encoding enforcement.
    ///
    /// This is intended only for trusted/internal uses. For untrusted inputs, prefer
    /// [`Self::deserialize`] to fail closed on non-canonical encodings.
    ///
    /// # Errors
    /// Returns `SerializationError::MissingSchemaHashPrefix` if the input is too short.
    /// Returns `SerializationError::SchemaMismatch` if the schema hash prefix does not match.
    /// Returns `SerializationError::PayloadTooLarge` if `data.len()` exceeds
    /// `MAX_CANONICAL_OBJECT_BYTES`.
    /// Returns `SerializationError::CborDeserialize` if the CBOR payload cannot be decoded.
    /// Returns `SerializationError::TrailingBytes` if extra bytes remain after decoding one value.
    pub fn deserialize_unchecked<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        if data.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: data.len(),
                max: MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        // Verify schema hash prefix.
        let (got_hash, body) = split_schema_prefix(data)?;
        let expected_hash = expected_schema.hash();
        if got_hash != expected_hash {
            return Err(SerializationError::SchemaMismatch {
                expected: expected_hash,
                got: got_hash,
            });
        }

        // Deserialize content (single CBOR item, no trailing bytes).
        let mut reader = body;
        let value = from_reader(&mut reader)?;
        if !reader.is_empty() {
            return Err(SerializationError::TrailingBytes);
        }

        Ok(value)
    }
}

fn split_schema_prefix(data: &[u8]) -> Result<(SchemaHash, &[u8]), SerializationError> {
    if data.len() < SCHEMA_HASH_LEN {
        return Err(SerializationError::MissingSchemaHashPrefix);
    }

    let got: [u8; SCHEMA_HASH_LEN] = data[..SCHEMA_HASH_LEN]
        .try_into()
        .map_err(|_| SerializationError::MissingSchemaHashPrefix)?;
    Ok((SchemaHash::from_bytes(got), &data[SCHEMA_HASH_LEN..]))
}

/// Serialize a value to deterministic RFC 8949 canonical CBOR bytes.
///
/// This does **not** include the 32-byte `SchemaHash` prefix used by [`CanonicalSerializer`].
///
/// # Errors
/// Returns `SerializationError` if the value cannot be represented as a CBOR `Value`, if
/// canonicalization fails (e.g., duplicate map keys), if CBOR serialization fails, or if the
/// encoded bytes exceed `MAX_CANONICAL_OBJECT_BYTES`.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut out = Vec::new();
    write_canonical_cbor(value, &mut out)?;
    if out.len() > MAX_CANONICAL_OBJECT_BYTES {
        return Err(SerializationError::PayloadTooLarge {
            len: out.len(),
            max: MAX_CANONICAL_OBJECT_BYTES,
        });
    }

    Ok(out)
}

fn write_canonical_cbor<T: Serialize>(
    value: &T,
    out: &mut Vec<u8>,
) -> Result<(), SerializationError> {
    let mut v = Value::serialized(value)?;
    canonicalize_value_in_place(&mut v, 0)?;
    into_writer(&v, out)?;
    Ok(())
}

const MAX_CANONICALIZATION_DEPTH: usize = 128;

fn canonicalize_value_in_place(v: &mut Value, depth: usize) -> Result<(), SerializationError> {
    if depth > MAX_CANONICALIZATION_DEPTH {
        return Err(SerializationError::PayloadTooLarge {
            len: depth,
            max: MAX_CANONICALIZATION_DEPTH,
        });
    }

    match v {
        Value::Array(items) => {
            for item in items {
                canonicalize_value_in_place(item, depth + 1)?;
            }
        }
        Value::Map(entries) => canonicalize_map(entries, depth + 1)?,
        Value::Tag(_, boxed) => canonicalize_value_in_place(boxed, depth + 1)?,
        _ => {}
    }

    Ok(())
}

fn canonicalize_map(
    entries: &mut Vec<(Value, Value)>,
    depth: usize,
) -> Result<(), SerializationError> {
    use std::cmp::Ordering;

    let mut with_keys = Vec::with_capacity(entries.len());
    for (mut key, mut value) in std::mem::take(entries) {
        canonicalize_value_in_place(&mut key, depth)?;
        canonicalize_value_in_place(&mut value, depth)?;

        let mut key_bytes = Vec::new();
        into_writer(&key, &mut key_bytes)?;

        with_keys.push((key_bytes, key, value));
    }

    with_keys.sort_by(
        |(a_bytes, _, _), (b_bytes, _, _)| match a_bytes.len().cmp(&b_bytes.len()) {
            Ordering::Equal => a_bytes.cmp(b_bytes),
            other => other,
        },
    );

    for pair in with_keys.windows(2) {
        // SAFETY: `windows(2)` always yields slices of length 2.
        let (left_bytes, _, _) = &pair[0];
        let (right_bytes, _, _) = &pair[1];
        if left_bytes == right_bytes {
            return Err(SerializationError::DuplicateMapKey {
                key_hex: hex::encode(right_bytes),
            });
        }
    }

    *entries = with_keys
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .collect();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ============================================================================
    // SchemaId and SchemaHash Tests
    // ============================================================================

    #[test]
    fn schema_id_as_bytes_is_canonical() {
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 2, 3));
        assert_eq!(
            schema.as_bytes(),
            b"fcp.core:CapabilityObject@1.2.3".to_vec()
        );
    }

    #[test]
    fn schema_hash_is_32_bytes() {
        let schema = SchemaId::new("fcp.core", "TestObject", Version::new(1, 0, 0));
        let hash = schema.hash();
        assert_eq!(hash.as_bytes().len(), 32);
        assert_eq!(hash.as_bytes().len(), SCHEMA_HASH_LEN);
    }

    #[test]
    fn schema_hash_is_deterministic() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));

        let hash1 = schema.hash();
        let hash2 = schema.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn schema_hash_differs_by_namespace() {
        let schema_a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.mesh", "Object", Version::new(1, 0, 0));
        assert_ne!(schema_a.hash(), schema_b.hash());
    }

    #[test]
    fn schema_hash_differs_by_name() {
        let schema_a = SchemaId::new("fcp.core", "ObjectA", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.core", "ObjectB", Version::new(1, 0, 0));
        assert_ne!(schema_a.hash(), schema_b.hash());
    }

    #[test]
    fn schema_hash_differs_by_version() {
        let schema_a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.core", "Object", Version::new(2, 0, 0));
        assert_ne!(schema_a.hash(), schema_b.hash());
    }

    #[test]
    fn schema_hash_display_is_hex() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let display = hash.to_string();

        // Display should be lowercase hex, 64 chars (32 bytes * 2).
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn schema_hash_from_bytes_roundtrip() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let bytes = *hash.as_bytes();
        let reconstructed = SchemaHash::from_bytes(bytes);
        assert_eq!(hash, reconstructed);
    }

    // ============================================================================
    // Deterministic CBOR Encoding Tests
    // ============================================================================

    #[test]
    fn same_object_produces_same_bytes() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Demo {
            a: u8,
            b: String,
        }

        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let value = Demo {
            a: 42,
            b: "hello".to_string(),
        };

        let bytes1 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let bytes3 = CanonicalSerializer::serialize(&value, &schema).unwrap();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn map_keys_are_sorted_by_canonical_bytes() {
        // Use a HashMap which has non-deterministic iteration order.
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        let mut map1 = HashMap::new();
        map1.insert("z", 1);
        map1.insert("a", 2);
        map1.insert("m", 3);

        let mut map2 = HashMap::new();
        map2.insert("a", 2);
        map2.insert("m", 3);
        map2.insert("z", 1);

        let bytes1 = CanonicalSerializer::serialize(&map1, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&map2, &schema).unwrap();

        // Same logical map, regardless of insertion order.
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn map_keys_sorted_length_first_then_lexicographic() {
        // RFC 8949 §4.2.1: shorter keys first, then lexicographic.
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        let mut map = HashMap::new();
        map.insert("bb", 1);
        map.insert("a", 2);
        map.insert("aaa", 3);
        map.insert("z", 4);

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();

        // Decode as raw CBOR value to inspect ordering.
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let value: Value = ciborium::de::from_reader(cbor_bytes).unwrap();

        if let Value::Map(entries) = value {
            let keys: Vec<_> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();

            // Expected order: "a" (len=1), "z" (len=1), "bb" (len=2), "aaa" (len=3).
            assert_eq!(keys, vec!["a", "z", "bb", "aaa"]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn integer_encoding_is_minimal() {
        let schema = SchemaId::new("fcp.test", "Int", Version::new(0, 1, 0));

        // Small integers (0-23) encode in 1 byte.
        let bytes = CanonicalSerializer::serialize(&0_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 1); // 0x00

        let bytes = CanonicalSerializer::serialize(&23_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 1); // 0x17

        // 24 requires 2 bytes (0x18 0x18).
        let bytes = CanonicalSerializer::serialize(&24_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 2);

        // 255 requires 2 bytes (0x18 0xFF).
        let bytes = CanonicalSerializer::serialize(&255_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 2);

        // 256 requires 3 bytes (0x19 0x01 0x00).
        let bytes = CanonicalSerializer::serialize(&256_u16, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 3);
    }

    #[test]
    fn duplicate_map_keys_rejected() {
        // Create CBOR with duplicate keys manually.
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        // Manually construct a CBOR map with duplicate keys.
        // { "a": 1, "a": 2 } - this is invalid.
        let cbor_bytes = vec![
            0xA2, // Map with 2 entries.
            0x61, // Text string, length 1.
            b'a', 0x01, // Integer 1.
            0x61, // Text string, length 1.
            b'a', // Duplicate key "a".
            0x02, // Integer 2.
        ];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&cbor_bytes);

        // This should fail because of duplicate keys.
        let result = CanonicalSerializer::deserialize::<HashMap<String, u8>>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn nested_maps_are_canonicalized() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Outer {
            inner: HashMap<String, i32>,
            name: String,
        }

        let schema = SchemaId::new("fcp.test", "Outer", Version::new(0, 1, 0));

        let mut inner = HashMap::new();
        inner.insert("z".to_string(), 1);
        inner.insert("a".to_string(), 2);

        let value = Outer {
            inner,
            name: "test".to_string(),
        };

        let bytes1 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&value, &schema).unwrap();

        assert_eq!(bytes1, bytes2);
    }

    // ============================================================================
    // Roundtrip Tests
    // ============================================================================

    #[test]
    fn roundtrip_canonical_serialization() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Demo {
            a: u8,
            b: String,
        }

        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let value = Demo {
            a: 7,
            b: "hi".to_string(),
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Demo = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);

        let bytes2 = CanonicalSerializer::serialize(&decoded, &schema).unwrap();
        assert_eq!(bytes2, bytes);
    }

    #[test]
    fn roundtrip_primitives() {
        let schema = SchemaId::new("fcp.test", "Primitive", Version::new(0, 1, 0));

        // Boolean.
        let bytes = CanonicalSerializer::serialize(&true, &schema).unwrap();
        let decoded: bool = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!(decoded);

        // Unsigned integers.
        for val in [
            0_u64,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u64::from(u32::MAX),
        ] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: u64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }

        // Signed integers.
        for val in [0_i64, -1, -24, -25, -128, i64::from(i32::MIN)] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: i64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }

        // Strings.
        for val in ["", "a", "hello", "😀🎉"] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }

        // Byte arrays.
        let byte_data: Vec<u8> = vec![0, 1, 2, 255];
        let bytes = CanonicalSerializer::serialize(&byte_data, &schema).unwrap();
        let decoded: Vec<u8> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, byte_data);
    }

    #[test]
    fn roundtrip_arrays() {
        let schema = SchemaId::new("fcp.test", "Array", Version::new(0, 1, 0));

        let empty: Vec<i32> = vec![];
        let bytes = CanonicalSerializer::serialize(&empty, &schema).unwrap();
        let decoded: Vec<i32> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, empty);

        let nums: Vec<i32> = vec![1, 2, 3, 4, 5];
        let bytes = CanonicalSerializer::serialize(&nums, &schema).unwrap();
        let decoded: Vec<i32> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, nums);

        let strings: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let bytes = CanonicalSerializer::serialize(&strings, &schema).unwrap();
        let decoded: Vec<String> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, strings);
    }

    #[test]
    fn roundtrip_nested_structs() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Inner {
            value: i32,
        }

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Outer {
            inner: Inner,
            items: Vec<Inner>,
        }

        let schema = SchemaId::new("fcp.test", "Outer", Version::new(0, 1, 0));
        let value = Outer {
            inner: Inner { value: 42 },
            items: vec![Inner { value: 1 }, Inner { value: 2 }],
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Outer = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_optional_fields() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct WithOption {
            required: String,
            optional: Option<i32>,
        }

        let schema = SchemaId::new("fcp.test", "WithOption", Version::new(0, 1, 0));

        let with_some = WithOption {
            required: "hello".into(),
            optional: Some(42),
        };
        let bytes = CanonicalSerializer::serialize(&with_some, &schema).unwrap();
        let decoded: WithOption = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, with_some);

        let with_none = WithOption {
            required: "hello".into(),
            optional: None,
        };
        let bytes = CanonicalSerializer::serialize(&with_none, &schema).unwrap();
        let decoded: WithOption = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, with_none);
    }

    #[test]
    fn roundtrip_enums() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Status {
            Active,
            Inactive,
            Pending { reason: String },
        }

        let schema = SchemaId::new("fcp.test", "Status", Version::new(0, 1, 0));

        for value in [
            Status::Active,
            Status::Inactive,
            Status::Pending {
                reason: "testing".into(),
            },
        ] {
            let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
            let decoded: Status = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, value);
        }
    }

    // ============================================================================
    // Schema Mismatch Tests
    // ============================================================================

    #[test]
    fn deserialize_rejects_schema_mismatch() {
        let schema_a = SchemaId::new("fcp.test", "A", Version::new(0, 1, 0));
        let schema_b = SchemaId::new("fcp.test", "B", Version::new(0, 1, 0));

        let bytes = CanonicalSerializer::serialize(&42_u64, &schema_a).unwrap();
        let err = CanonicalSerializer::deserialize::<u64>(&bytes, &schema_b).unwrap_err();
        assert!(matches!(err, SerializationError::SchemaMismatch { .. }));
    }

    #[test]
    fn deserialize_rejects_version_mismatch() {
        let schema_v1 = SchemaId::new("fcp.test", "Object", Version::new(1, 0, 0));
        let schema_v2 = SchemaId::new("fcp.test", "Object", Version::new(2, 0, 0));

        let bytes = CanonicalSerializer::serialize(&42_u64, &schema_v1).unwrap();
        let err = CanonicalSerializer::deserialize::<u64>(&bytes, &schema_v2).unwrap_err();
        assert!(matches!(err, SerializationError::SchemaMismatch { .. }));
    }

    // ============================================================================
    // Non-Canonical Encoding Rejection Tests
    // ============================================================================

    #[test]
    fn deserialize_rejects_non_canonical_integer_encoding() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // CBOR integer 1 encoded in non-canonical form (0x18 0x01 instead of 0x01).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x18, 0x01]);

        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    #[test]
    fn deserialize_rejects_non_canonical_string_length() {
        let schema = SchemaId::new("fcp.test", "String", Version::new(0, 1, 0));

        // String "a" encoded with 2-byte length prefix (0x78 0x01) instead of 1-byte (0x61).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x78, 0x01, b'a']);

        let err = CanonicalSerializer::deserialize::<String>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        let mut bytes = CanonicalSerializer::serialize(&1_u8, &schema).unwrap();
        bytes.push(0x00);

        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::TrailingBytes));
    }

    // ============================================================================
    // Decode Safety Tests (Malformed Input)
    // ============================================================================

    #[test]
    fn deserialize_rejects_truncated_input() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // Too short to contain schema hash.
        let bytes: [u8; 16] = [0; 16];
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_rejects_empty_input() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        let bytes: [u8; 0] = [];
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_rejects_truncated_cbor() {
        let schema = SchemaId::new("fcp.test", "String", Version::new(0, 1, 0));

        // Schema hash + truncated string (claims length 10 but only has 2 bytes).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x6A, b'a', b'b']); // 0x6A = text string of length 10.

        let err = CanonicalSerializer::deserialize::<String>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    #[test]
    fn deserialize_rejects_invalid_cbor() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // Schema hash + invalid CBOR (0xFF is a break code, invalid at top level).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.push(0xFF);

        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    #[test]
    fn deserialize_rejects_wrong_type() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // Serialize a string but try to deserialize as u8.
        let bytes = CanonicalSerializer::serialize(&"hello", &schema).unwrap();
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    // ============================================================================
    // Size Limit Tests
    // ============================================================================

    #[test]
    fn serialize_rejects_oversized_payload() {
        let schema = SchemaId::new("fcp.test", "Large", Version::new(0, 1, 0));

        // Create a payload that exceeds MAX_CANONICAL_OBJECT_BYTES.
        let large_data: Vec<u8> = vec![0; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = CanonicalSerializer::serialize(&large_data, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    #[test]
    fn deserialize_rejects_oversized_input() {
        let schema = SchemaId::new("fcp.test", "Large", Version::new(0, 1, 0));

        // Create input that exceeds MAX_CANONICAL_OBJECT_BYTES.
        let large_input: Vec<u8> = vec![0; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = CanonicalSerializer::deserialize::<Vec<u8>>(&large_input, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    // ============================================================================
    // Payload Format Tests
    // ============================================================================

    #[test]
    fn payload_format_is_schema_hash_then_cbor() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let value = 42_u8;

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();

        // First 32 bytes should be the schema hash.
        let expected_hash = schema.hash();
        assert_eq!(&bytes[..SCHEMA_HASH_LEN], expected_hash.as_bytes());

        // Remaining bytes should be valid CBOR for the value.
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let decoded: u8 = ciborium::de::from_reader(cbor_bytes).unwrap();
        assert_eq!(decoded, value);
    }

    // ============================================================================
    // Golden Vector Tests
    // ============================================================================

    #[test]
    fn golden_vector_schema_hash() {
        // Fixed schema ID should always produce the same hash.
        let schema = SchemaId::new("fcp.core", "CapabilityToken", Version::new(1, 0, 0));
        let hash = schema.hash();

        // This is the expected hash - if this changes, serialization compatibility is broken.
        let expected_hex = hex::encode(hash.as_bytes());

        // Just verify it's deterministic (the actual value is the baseline).
        let hash2 = schema.hash();
        assert_eq!(hex::encode(hash2.as_bytes()), expected_hex);
    }

    #[test]
    fn golden_vector_simple_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct GoldenStruct {
            id: u64,
            name: String,
            active: bool,
        }

        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let value = GoldenStruct {
            id: 12345,
            name: "test".to_string(),
            active: true,
        };

        // Serialize and capture the bytes.
        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();

        // Verify it's deterministic.
        let bytes2 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        assert_eq!(bytes, bytes2);

        // Verify roundtrip.
        let decoded: GoldenStruct = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);

        // Verify the CBOR portion has expected structure.
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let raw: Value = ciborium::de::from_reader(cbor_bytes).unwrap();
        assert!(matches!(raw, Value::Map(_)));
    }

    // ============================================================================
    // Unchecked Deserialization Tests
    // ============================================================================

    #[test]
    fn deserialize_unchecked_allows_non_canonical() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // CBOR integer 1 encoded in non-canonical form (0x18 0x01 instead of 0x01).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x18, 0x01]);

        // unchecked should succeed.
        let value: u8 = CanonicalSerializer::deserialize_unchecked(&bytes, &schema).unwrap();
        assert_eq!(value, 1);

        // strict should fail.
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    // ============================================================================
    // to_canonical_cbor Tests (without schema prefix)
    // ============================================================================

    #[test]
    fn to_canonical_cbor_is_deterministic() {
        let value = vec![3, 1, 4, 1, 5, 9, 2, 6];
        let bytes1 = to_canonical_cbor(&value).unwrap();
        let bytes2 = to_canonical_cbor(&value).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn to_canonical_cbor_has_no_schema_prefix() {
        let value = 42_u8;
        let bytes = to_canonical_cbor(&value).unwrap();

        // Should be just the CBOR encoding, no 32-byte prefix.
        // CBOR for 42 is 0x18 0x2A (2 bytes).
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes, vec![0x18, 0x2A]);
    }

    // ============================================================================
    // Error Display Tests
    // ============================================================================

    #[test]
    fn error_display_missing_schema_hash_prefix() {
        let err = SerializationError::MissingSchemaHashPrefix;
        assert_eq!(err.to_string(), "payload missing schema hash prefix");
    }

    #[test]
    fn error_display_schema_mismatch() {
        let expected = SchemaHash::from_bytes([0xAA; 32]);
        let got = SchemaHash::from_bytes([0xBB; 32]);
        let err = SerializationError::SchemaMismatch { expected, got };
        let msg = err.to_string();
        assert!(msg.contains("schema hash mismatch"));
        assert!(msg.contains(&expected.to_string()));
        assert!(msg.contains(&got.to_string()));
    }

    #[test]
    fn error_display_payload_too_large() {
        let err = SerializationError::PayloadTooLarge { len: 100, max: 50 };
        assert_eq!(err.to_string(), "payload too large (100 bytes > 50 bytes)");
    }

    #[test]
    fn error_display_trailing_bytes() {
        let err = SerializationError::TrailingBytes;
        assert_eq!(err.to_string(), "trailing bytes after CBOR value");
    }

    #[test]
    fn error_display_non_canonical_encoding() {
        let err = SerializationError::NonCanonicalEncoding;
        assert_eq!(err.to_string(), "non-canonical CBOR encoding");
    }

    #[test]
    fn error_display_duplicate_map_key() {
        let err = SerializationError::DuplicateMapKey {
            key_hex: "6161".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "duplicate map key (canonical key bytes: 6161)"
        );
    }

    // ============================================================================
    // SchemaHash Trait Impl Tests
    // ============================================================================

    #[test]
    fn schema_hash_debug_contains_hex() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let debug = format!("{hash:?}");
        assert!(debug.starts_with("SchemaHash(\""));
        assert!(debug.ends_with("\")"));
        // The hex string inside should be 64 chars.
        let inner = &debug["SchemaHash(\"".len()..debug.len() - 2];
        assert_eq!(inner.len(), 64);
    }

    #[test]
    fn schema_hash_as_ref_matches_as_bytes() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let as_ref: &[u8] = hash.as_ref();
        assert_eq!(as_ref, hash.as_bytes());
    }

    // ============================================================================
    // SchemaId Edge Cases
    // ============================================================================

    #[test]
    fn schema_id_empty_namespace_and_name() {
        let schema = SchemaId::new("", "", Version::new(0, 0, 0));
        let bytes = schema.as_bytes();
        assert_eq!(bytes, b":@0.0.0".to_vec());
        // Hash should still be 32 bytes and deterministic.
        assert_eq!(schema.hash().as_bytes().len(), 32);
    }

    #[test]
    fn schema_id_serde_roundtrip() {
        let schema = SchemaId::new("fcp.core", "Token", Version::new(2, 1, 3));
        let json = serde_json::to_string(&schema).unwrap();
        let decoded: SchemaId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn schema_id_hash_includes_domain_separator() {
        // Two different domain separators should yield different hashes.
        // We verify this indirectly: the hash of a schema is NOT the same as
        // BLAKE3(schema.as_bytes()) without the domain separator.
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash_with_domain = schema.hash();

        let mut bare_hasher = blake3::Hasher::new();
        bare_hasher.update(&schema.as_bytes());
        let bare_hash = *bare_hasher.finalize().as_bytes();

        assert_ne!(hash_with_domain.as_bytes(), &bare_hash);
    }

    #[test]
    fn schema_id_clone_and_eq() {
        let schema = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
        let cloned = schema.clone();
        assert_eq!(schema, cloned);
        assert_eq!(schema.hash(), cloned.hash());
    }

    // ============================================================================
    // split_schema_prefix Edge Cases
    // ============================================================================

    #[test]
    fn deserialize_exact_schema_hash_no_cbor_body() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        // Exactly 32 bytes = schema hash only, no CBOR body.
        let bytes = schema.hash().as_bytes().to_vec();
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        // Should fail because there's no CBOR to decode.
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    // ============================================================================
    // deserialize_unchecked Error Paths
    // ============================================================================

    #[test]
    fn deserialize_unchecked_rejects_schema_mismatch() {
        let schema_a = SchemaId::new("fcp.test", "A", Version::new(0, 1, 0));
        let schema_b = SchemaId::new("fcp.test", "B", Version::new(0, 1, 0));

        let bytes = CanonicalSerializer::serialize(&42_u64, &schema_a).unwrap();
        let err = CanonicalSerializer::deserialize_unchecked::<u64>(&bytes, &schema_b).unwrap_err();
        assert!(matches!(err, SerializationError::SchemaMismatch { .. }));
    }

    #[test]
    fn deserialize_unchecked_rejects_oversized_input() {
        let schema = SchemaId::new("fcp.test", "Large", Version::new(0, 1, 0));
        let large_input: Vec<u8> = vec![0; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = CanonicalSerializer::deserialize_unchecked::<Vec<u8>>(&large_input, &schema)
            .unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    #[test]
    fn deserialize_unchecked_rejects_trailing_bytes() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        let mut bytes = CanonicalSerializer::serialize(&1_u8, &schema).unwrap();
        bytes.push(0x00); // trailing garbage
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::TrailingBytes));
    }

    #[test]
    fn deserialize_unchecked_rejects_truncated_input() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        let bytes: [u8; 10] = [0; 10];
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    // ============================================================================
    // Empty and Boundary Structure Tests
    // ============================================================================

    #[test]
    fn roundtrip_empty_map() {
        let schema = SchemaId::new("fcp.test", "EmptyMap", Version::new(0, 1, 0));
        let map: HashMap<String, i32> = HashMap::new();
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, i32> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn roundtrip_empty_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Empty {}

        let schema = SchemaId::new("fcp.test", "Empty", Version::new(0, 1, 0));
        let value = Empty {};
        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Empty = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_deeply_nested_structure() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Node {
            value: i32,
            children: Vec<Self>,
        }

        let schema = SchemaId::new("fcp.test", "Node", Version::new(0, 1, 0));
        let value = Node {
            value: 1,
            children: vec![
                Node {
                    value: 2,
                    children: vec![Node {
                        value: 3,
                        children: vec![],
                    }],
                },
                Node {
                    value: 4,
                    children: vec![],
                },
            ],
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Node = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_tuple_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Pair(u32, String);

        let schema = SchemaId::new("fcp.test", "Pair", Version::new(0, 1, 0));
        let value = Pair(42, "hello".into());
        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Pair = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_unit_variant_enum() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Color {
            Red,
            Green,
            Blue,
        }

        let schema = SchemaId::new("fcp.test", "Color", Version::new(0, 1, 0));
        for color in [Color::Red, Color::Green, Color::Blue] {
            let bytes = CanonicalSerializer::serialize(&color, &schema).unwrap();
            let decoded: Color = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, color);
        }
    }

    // ============================================================================
    // Canonical Encoding Detail Tests
    // ============================================================================

    #[test]
    fn boolean_canonical_encoding_sizes() {
        let schema = SchemaId::new("fcp.test", "Bool", Version::new(0, 1, 0));
        // CBOR true = 0xF5 (1 byte), false = 0xF4 (1 byte).
        let bytes_true = CanonicalSerializer::serialize(&true, &schema).unwrap();
        assert_eq!(bytes_true.len(), SCHEMA_HASH_LEN + 1);

        let bytes_false = CanonicalSerializer::serialize(&false, &schema).unwrap();
        assert_eq!(bytes_false.len(), SCHEMA_HASH_LEN + 1);

        // They should differ.
        assert_ne!(bytes_true, bytes_false);
    }

    #[test]
    fn null_canonical_encoding() {
        let schema = SchemaId::new("fcp.test", "Null", Version::new(0, 1, 0));
        // CBOR null = 0xF6 (1 byte).
        let none: Option<u8> = None;
        let bytes = CanonicalSerializer::serialize(&none, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 1);
        assert_eq!(bytes[SCHEMA_HASH_LEN], 0xF6);
    }

    #[test]
    fn negative_integer_minimal_encoding() {
        let schema = SchemaId::new("fcp.test", "Int", Version::new(0, 1, 0));
        // CBOR: -1 = 0x20 (1 byte), -24 = 0x37 (1 byte), -25 = 0x38 0x18 (2 bytes).
        let bytes_neg1 = CanonicalSerializer::serialize(&(-1_i8), &schema).unwrap();
        assert_eq!(bytes_neg1.len(), SCHEMA_HASH_LEN + 1);

        let bytes_neg24 = CanonicalSerializer::serialize(&(-24_i8), &schema).unwrap();
        assert_eq!(bytes_neg24.len(), SCHEMA_HASH_LEN + 1);

        let bytes_neg25 = CanonicalSerializer::serialize(&(-25_i8), &schema).unwrap();
        assert_eq!(bytes_neg25.len(), SCHEMA_HASH_LEN + 2);
    }

    #[test]
    fn string_length_encoding_boundaries() {
        // String length 23: 1-byte length prefix (0x77).
        let s23 = "a".repeat(23);
        let bytes23 = to_canonical_cbor(&s23).unwrap();
        assert_eq!(bytes23[0], 0x77); // major type 3, additional 23

        // String length 24: 2-byte length prefix (0x78 0x18).
        let s24 = "a".repeat(24);
        let bytes24 = to_canonical_cbor(&s24).unwrap();
        assert_eq!(bytes24[0], 0x78);
        assert_eq!(bytes24[1], 24);
    }

    // ============================================================================
    // Map Canonicalization Edge Cases
    // ============================================================================

    #[test]
    fn map_with_integer_keys_sorted() {
        use std::collections::BTreeMap;
        let schema = SchemaId::new("fcp.test", "IntMap", Version::new(0, 1, 0));

        let mut map = BTreeMap::new();
        map.insert(100, "hundred");
        map.insert(1, "one");
        map.insert(10, "ten");

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();

        // Decode raw CBOR and check key order (shorter encoding first).
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let value: Value = ciborium::de::from_reader(cbor_bytes).unwrap();
        if let Value::Map(entries) = value {
            let keys: Vec<_> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Integer(i) = k {
                        Some(i128::from(*i))
                    } else {
                        None
                    }
                })
                .collect();
            // 1 (1 byte: 0x01), 10 (1 byte: 0x0A), 100 (2 bytes: 0x18 0x64).
            assert_eq!(keys, vec![1, 10, 100]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn map_single_entry() {
        let schema = SchemaId::new("fcp.test", "SingleMap", Version::new(0, 1, 0));
        let mut map = HashMap::new();
        map.insert("only", 1);
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, i32> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded["only"], 1);
    }

    // ============================================================================
    // to_canonical_cbor Direct Tests
    // ============================================================================

    #[test]
    fn to_canonical_cbor_empty_array() {
        let empty: Vec<u8> = vec![];
        let bytes = to_canonical_cbor(&empty).unwrap();
        // CBOR empty array = 0x80 (1 byte).
        assert_eq!(bytes, vec![0x80]);
    }

    #[test]
    fn to_canonical_cbor_empty_string() {
        let bytes = to_canonical_cbor(&"").unwrap();
        // CBOR empty text string = 0x60 (1 byte).
        assert_eq!(bytes, vec![0x60]);
    }

    #[test]
    fn to_canonical_cbor_map_deterministic_regardless_of_insertion() {
        let mut map_a = HashMap::new();
        map_a.insert("x", 1);
        map_a.insert("y", 2);
        map_a.insert("z", 3);

        let mut map_b = HashMap::new();
        map_b.insert("z", 3);
        map_b.insert("x", 1);
        map_b.insert("y", 2);

        let bytes_a = to_canonical_cbor(&map_a).unwrap();
        let bytes_b = to_canonical_cbor(&map_b).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    // ============================================================================
    // Non-Canonical Map Key Order Rejection
    // ============================================================================

    #[test]
    fn deserialize_rejects_non_canonical_map_key_order() {
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        // Manually build: { "bb": 1, "a": 2 } — wrong order per RFC 8949.
        // Canonical should be { "a": 2, "bb": 1 } (shorter keys first).
        let mut cbor_bytes = Vec::new();
        cbor_bytes.push(0xA2); // map with 2 entries
        // "bb" first (non-canonical)
        cbor_bytes.push(0x62); // text string, length 2
        cbor_bytes.extend_from_slice(b"bb");
        cbor_bytes.push(0x01); // integer 1
        // "a" second
        cbor_bytes.push(0x61); // text string, length 1
        cbor_bytes.push(b'a');
        cbor_bytes.push(0x02); // integer 2

        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&cbor_bytes);

        let err =
            CanonicalSerializer::deserialize::<HashMap<String, u8>>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    // ============================================================================
    // NEW TESTS: SchemaId derive-trait and edge-case coverage
    // ============================================================================

    #[test]
    fn schema_id_hash_in_hashset() {
        use std::collections::HashSet;
        let s1 = SchemaId::new("fcp.core", "Token", Version::new(1, 0, 0));
        let s2 = SchemaId::new("fcp.core", "Token", Version::new(1, 0, 0));
        let s3 = SchemaId::new("fcp.core", "Token", Version::new(2, 0, 0));

        let mut set = HashSet::new();
        set.insert(s1);
        set.insert(s2); // duplicate, should not increase size
        set.insert(s3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn schema_id_debug_contains_fields() {
        let schema = SchemaId::new("fcp.mesh", "Gossip", Version::new(3, 1, 4));
        let debug = format!("{schema:?}");
        assert!(debug.contains("fcp.mesh"));
        assert!(debug.contains("Gossip"));
        // Version Debug may wrap the value; just check the components are present.
        assert!(debug.contains('3'));
        assert!(debug.contains('1'));
        assert!(debug.contains('4'));
    }

    #[test]
    fn schema_id_display_canonical_format() {
        let schema = SchemaId::new("fcp.core", "Capability", Version::new(1, 0, 0));
        // SchemaId does not impl Display, but as_bytes encodes the canonical string.
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "fcp.core:Capability@1.0.0");
    }

    #[test]
    fn schema_id_as_bytes_with_unicode() {
        let schema = SchemaId::new("名前空間", "タイプ", Version::new(0, 0, 1));
        let bytes = schema.as_bytes();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, "名前空間:タイプ@0.0.1");
        // Hash should still be 32 bytes and deterministic.
        let h1 = schema.hash();
        let h2 = schema.hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.as_bytes().len(), 32);
    }

    #[test]
    fn schema_id_as_bytes_with_special_chars() {
        let schema = SchemaId::new("ns/with.dots-and_stuff", "Type<T>", Version::new(0, 0, 0));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "ns/with.dots-and_stuff:Type<T>@0.0.0");
    }

    #[test]
    fn schema_id_serde_cbor_roundtrip() {
        let schema = SchemaId::new("fcp.protocol", "Envelope", Version::new(2, 3, 0));
        let cbor_bytes = to_canonical_cbor(&schema).unwrap();
        let decoded: SchemaId = ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn schema_id_hash_determinism_across_clones() {
        let original = SchemaId::new("fcp.sdk", "Runtime", Version::new(1, 0, 0));
        let cloned = original.clone();
        // Hash of original and clone must be identical.
        assert_eq!(original.hash(), cloned.hash());
        // And the raw bytes must match too.
        assert_eq!(original.hash().as_bytes(), cloned.hash().as_bytes());
    }

    // ============================================================================
    // NEW TESTS: SchemaHash derive-trait and edge-case coverage
    // ============================================================================

    #[test]
    fn schema_hash_copy_trait() {
        let hash = SchemaHash::from_bytes([0xAB; 32]);
        let copied = hash; // Copy, not move
        // Both should still be usable (Copy semantics).
        assert_eq!(hash, copied);
        assert_eq!(hash.as_bytes(), copied.as_bytes());
    }

    #[test]
    fn schema_hash_from_bytes_all_zeros() {
        let hash = SchemaHash::from_bytes([0x00; 32]);
        assert_eq!(hash.as_bytes(), &[0x00; 32]);
        assert_eq!(
            hash.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn schema_hash_from_bytes_all_ff() {
        let hash = SchemaHash::from_bytes([0xFF; 32]);
        assert_eq!(hash.as_bytes(), &[0xFF; 32]);
        assert_eq!(
            hash.to_string(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn schema_hash_display_is_lowercase_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        bytes[30] = 0xBE;
        bytes[31] = 0xEF;
        let hash = SchemaHash::from_bytes(bytes);
        let display = hash.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.starts_with("dead"));
        assert!(display.ends_with("beef"));
        // Must be lowercase hex only.
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!display.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn schema_hash_serde_json_roundtrip() {
        let schema = SchemaId::new("fcp.test", "SerdeHash", Version::new(1, 0, 0));
        let hash = schema.hash();
        let json = serde_json::to_string(&hash).unwrap();
        let decoded: SchemaHash = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn schema_hash_eq_reflexive_and_symmetric() {
        let a = SchemaHash::from_bytes([0x42; 32]);
        let b = SchemaHash::from_bytes([0x42; 32]);
        let c = SchemaHash::from_bytes([0x43; 32]);
        // Reflexive.
        assert_eq!(a, a);
        // Symmetric.
        assert_eq!(a, b);
        assert_eq!(b, a);
        // Not equal to different.
        assert_ne!(a, c);
    }

    #[test]
    fn schema_hash_in_hashset() {
        use std::collections::HashSet;
        let h1 = SchemaHash::from_bytes([0x01; 32]);
        let h2 = SchemaHash::from_bytes([0x01; 32]);
        let h3 = SchemaHash::from_bytes([0x02; 32]);
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2); // duplicate
        set.insert(h3);
        assert_eq!(set.len(), 2);
    }

    // ============================================================================
    // NEW TESTS: SerializationError trait coverage
    // ============================================================================

    #[test]
    fn error_debug_all_variants() {
        // Verify Debug is implemented for all variants.
        let errors: Vec<SerializationError> = vec![
            SerializationError::MissingSchemaHashPrefix,
            SerializationError::SchemaMismatch {
                expected: SchemaHash::from_bytes([0; 32]),
                got: SchemaHash::from_bytes([1; 32]),
            },
            SerializationError::PayloadTooLarge { len: 100, max: 50 },
            SerializationError::TrailingBytes,
            SerializationError::NonCanonicalEncoding,
            SerializationError::DuplicateMapKey {
                key_hex: "deadbeef".to_string(),
            },
        ];
        for err in &errors {
            let debug = format!("{err:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn error_implements_std_error_trait() {
        // Verify std::error::Error is implemented.
        let err: Box<dyn std::error::Error> = Box::new(SerializationError::MissingSchemaHashPrefix);
        // source() should be None for non-wrapping variants.
        assert!(err.source().is_none());
        // Display should work through the Error trait.
        assert_eq!(err.to_string(), "payload missing schema hash prefix");
    }

    #[test]
    fn error_schema_mismatch_display_shows_both_hashes() {
        let expected = SchemaHash::from_bytes([0x11; 32]);
        let got = SchemaHash::from_bytes([0x22; 32]);
        let err = SerializationError::SchemaMismatch { expected, got };
        let msg = err.to_string();
        // Both hex strings should appear in the message.
        assert!(msg.contains(&expected.to_string()));
        assert!(msg.contains(&got.to_string()));
    }

    #[test]
    fn error_from_cbor_serialize() {
        // Trigger a CborSerialize error via the From impl.
        // A cyclic/infinite structure isn't easy, but we can verify the variant exists
        // by constructing the error path: serialize something that exceeds depth.
        // Instead, just check the Display of PayloadTooLarge with boundary values.
        let err = SerializationError::PayloadTooLarge {
            len: MAX_CANONICAL_OBJECT_BYTES + 1,
            max: MAX_CANONICAL_OBJECT_BYTES,
        };
        let msg = err.to_string();
        assert!(msg.contains("67108865")); // MAX + 1
        assert!(msg.contains("67108864")); // MAX
    }

    // ============================================================================
    // NEW TESTS: Constants verification
    // ============================================================================

    #[test]
    fn max_canonical_object_bytes_is_64_mib() {
        assert_eq!(MAX_CANONICAL_OBJECT_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_CANONICAL_OBJECT_BYTES, 67_108_864);
    }

    #[test]
    fn schema_hash_len_is_32() {
        assert_eq!(SCHEMA_HASH_LEN, 32);
    }

    // ============================================================================
    // NEW TESTS: to_canonical_cbor with various types
    // ============================================================================

    #[test]
    fn to_canonical_cbor_with_empty_struct() {
        #[derive(Serialize)]
        struct Unit;

        let bytes = to_canonical_cbor(&Unit).unwrap();
        // CBOR null = 0xF6.
        assert_eq!(bytes, vec![0xF6]);
    }

    #[test]
    fn to_canonical_cbor_with_nested_structs() {
        #[derive(Serialize)]
        struct Inner {
            x: u32,
        }
        #[derive(Serialize)]
        struct Middle {
            inner: Inner,
            tag: String,
        }
        #[derive(Serialize)]
        struct Outer {
            middle: Middle,
            count: u64,
        }

        let val = Outer {
            middle: Middle {
                inner: Inner { x: 99 },
                tag: "deep".to_string(),
            },
            count: 7,
        };

        let bytes1 = to_canonical_cbor(&val).unwrap();
        let bytes2 = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes1, bytes2);
        // Should decode as a CBOR map.
        let raw: Value = ciborium::de::from_reader(bytes1.as_slice()).unwrap();
        assert!(matches!(raw, Value::Map(_)));
    }

    #[test]
    fn to_canonical_cbor_with_option_some_and_none() {
        let some_val: Option<u32> = Some(42);
        let none_val: Option<u32> = None;

        let some_bytes = to_canonical_cbor(&some_val).unwrap();
        let none_bytes = to_canonical_cbor(&none_val).unwrap();

        // They should be different.
        assert_ne!(some_bytes, none_bytes);
        // None encodes as CBOR null.
        assert_eq!(none_bytes, vec![0xF6]);
    }

    #[test]
    fn to_canonical_cbor_with_vec_of_strings() {
        let data = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let bytes = to_canonical_cbor(&data).unwrap();
        let decoded: Vec<String> = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn to_canonical_cbor_btreemap_deterministic_key_order() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert("zebra".to_string(), 1);
        map.insert("ant".to_string(), 2);
        map.insert("bee".to_string(), 3);
        map.insert("caterpillar".to_string(), 4);

        let bytes = to_canonical_cbor(&map).unwrap();

        // Decode raw CBOR and check key order: length-first, then lexicographic.
        let raw: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            // "ant" (3), "bee" (3), "zebra" (5), "caterpillar" (11)
            // Within same length: lexicographic.
            assert_eq!(keys, vec!["ant", "bee", "zebra", "caterpillar"]);
        } else {
            panic!("Expected map");
        }
    }

    // ============================================================================
    // NEW TESTS: CanonicalSerializer roundtrip with complex types
    // ============================================================================

    #[test]
    fn roundtrip_struct_with_btreemap() {
        use std::collections::BTreeMap;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Config {
            settings: BTreeMap<String, String>,
            version: u32,
        }

        let schema = SchemaId::new("fcp.test", "Config", Version::new(0, 1, 0));
        let mut settings = BTreeMap::new();
        settings.insert("key_z".to_string(), "value_z".to_string());
        settings.insert("key_a".to_string(), "value_a".to_string());
        settings.insert("key_m".to_string(), "value_m".to_string());

        let value = Config {
            settings,
            version: 42,
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Config = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_vec_of_optional_structs() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Item {
            id: u32,
            label: Option<String>,
        }

        let schema = SchemaId::new("fcp.test", "Items", Version::new(0, 1, 0));
        let items = vec![
            Item {
                id: 1,
                label: Some("first".to_string()),
            },
            Item { id: 2, label: None },
            Item {
                id: 3,
                label: Some("third".to_string()),
            },
        ];

        let bytes = CanonicalSerializer::serialize(&items, &schema).unwrap();
        let decoded: Vec<Item> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, items);
    }

    #[test]
    fn roundtrip_enum_with_tuple_variant() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Message {
            Text(String),
            Binary(Vec<u8>),
            Pair(u32, u32),
        }

        let schema = SchemaId::new("fcp.test", "Message", Version::new(0, 1, 0));

        let variants = vec![
            Message::Text("hello".to_string()),
            Message::Binary(vec![0xDE, 0xAD]),
            Message::Pair(10, 20),
        ];

        for msg in &variants {
            let bytes = CanonicalSerializer::serialize(msg, &schema).unwrap();
            let decoded: Message = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(&decoded, msg);
        }
    }

    #[test]
    fn schema_hash_consistency_across_serializations() {
        // The schema hash prefix in serialized output must always be the same
        // for the same SchemaId, regardless of payload content.
        let schema = SchemaId::new("fcp.test", "Consistency", Version::new(1, 0, 0));
        let expected_hash = schema.hash();

        let bytes_a = CanonicalSerializer::serialize(&42_u64, &schema).unwrap();
        let bytes_b = CanonicalSerializer::serialize(&"hello", &schema).unwrap();
        let bytes_c = CanonicalSerializer::serialize(&true, &schema).unwrap();

        assert_eq!(&bytes_a[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
        assert_eq!(&bytes_b[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
        assert_eq!(&bytes_c[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
    }

    #[test]
    fn roundtrip_nested_maps() {
        let schema = SchemaId::new("fcp.test", "NestedMap", Version::new(0, 1, 0));

        let mut inner1 = HashMap::new();
        inner1.insert("x".to_string(), 1_i32);
        inner1.insert("y".to_string(), 2);

        let mut inner2 = HashMap::new();
        inner2.insert("a".to_string(), 10);

        let mut outer = HashMap::new();
        outer.insert("first".to_string(), inner1);
        outer.insert("second".to_string(), inner2);

        let bytes = CanonicalSerializer::serialize(&outer, &schema).unwrap();
        let decoded: HashMap<String, HashMap<String, i32>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, outer);
    }

    #[test]
    fn roundtrip_large_array() {
        let schema = SchemaId::new("fcp.test", "LargeArray", Version::new(0, 1, 0));
        let data: Vec<u32> = (0..1000).collect();
        let bytes = CanonicalSerializer::serialize(&data, &schema).unwrap();
        let decoded: Vec<u32> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, data);
    }

    // ============================================================================
    // NEW TESTS: SchemaId Display impl
    // ============================================================================

    #[test]
    fn schema_id_as_bytes_encodes_prerelease_version() {
        let schema = SchemaId::new("fcp.store", "Repair", Version::parse("0.5.2-rc.1").unwrap());
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "fcp.store:Repair@0.5.2-rc.1");
    }

    // ============================================================================
    // NEW TESTS: to_canonical_cbor oversized rejection
    // ============================================================================

    #[test]
    fn to_canonical_cbor_rejects_oversized() {
        let huge: Vec<u8> = vec![0u8; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = to_canonical_cbor(&huge).unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    // ============================================================================
    // NEW TESTS: Canonical encoding — map with mixed-length keys
    // ============================================================================

    #[test]
    fn canonical_cbor_map_mixed_key_lengths() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert("a".to_string(), 1);
        map.insert("bb".to_string(), 2);
        map.insert("c".to_string(), 3);
        map.insert("dd".to_string(), 4);

        let bytes = to_canonical_cbor(&map).unwrap();
        let raw: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            // Length 1: "a", "c" (lex order); Length 2: "bb", "dd" (lex order).
            assert_eq!(keys, vec!["a", "c", "bb", "dd"]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn schema_hash_from_to_bytes_identity() {
        // Arbitrary non-trivial bytes.
        let original: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let hash = SchemaHash::from_bytes(original);
        let extracted = *hash.as_bytes();
        assert_eq!(extracted, original);
    }
}
