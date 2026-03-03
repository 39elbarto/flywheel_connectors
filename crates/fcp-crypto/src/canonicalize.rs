//! Signature canonicalization helpers for FCP2.
//!
//! Provides a single signing-bytes procedure to prevent cross-implementation drift:
//! 1. Define an "unsigned view" of an object (remove `signature`/`quorum_signatures` fields)
//! 2. Serialize using deterministic CBOR with schema-hash prefix
//! 3. For multi-signature vectors: sort lexicographically by `node_id` before hashing/signing/verifying

use crate::error::{CryptoError, CryptoResult};

/// Domain separation prefix for canonical signing.
pub const SIGNING_DOMAIN: &[u8] = b"FCP2-SIGN-V1";

/// Schema hash size for signing context.
pub const SCHEMA_HASH_SIZE: usize = 8;

/// Compute schema hash for signing context.
///
/// Uses BLAKE3 truncated to 8 bytes: `BLAKE3(schema_id)[0..8]`.
#[must_use]
pub fn schema_hash(schema_id: &str) -> [u8; SCHEMA_HASH_SIZE] {
    let hash = blake3::hash(schema_id.as_bytes());
    let mut result = [0u8; SCHEMA_HASH_SIZE];
    result.copy_from_slice(&hash.as_bytes()[..SCHEMA_HASH_SIZE]);
    result
}

/// Build canonical signing bytes for an object.
///
/// Format: `SIGNING_DOMAIN || schema_hash || cbor_bytes`
///
/// # Arguments
///
/// * `schema_id` - Schema identifier for the object type (e.g., "fcp.zone.ZoneKeyManifest/1.0.0")
/// * `cbor_bytes` - Deterministic CBOR encoding of the unsigned object
#[must_use]
pub fn canonical_signing_bytes(schema_id: &str, cbor_bytes: &[u8]) -> Vec<u8> {
    let schema = schema_hash(schema_id);
    let mut result = Vec::with_capacity(SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + cbor_bytes.len());
    result.extend_from_slice(SIGNING_DOMAIN);
    result.extend_from_slice(&schema);
    result.extend_from_slice(cbor_bytes);
    result
}

/// Sort node signatures lexicographically by `node_id` for multi-sig verification.
///
/// Returns indices in sorted order.
#[must_use]
pub fn sort_signatures_by_node_id(node_ids: &[&[u8]]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..node_ids.len()).collect();
    indices.sort_by_key(|&i| node_ids[i]);
    indices
}

/// Verify that signatures are properly sorted by `node_id`.
///
/// # Errors
///
/// Returns an error if signatures are not in lexicographic order.
pub fn verify_signature_order(node_ids: &[&[u8]]) -> CryptoResult<()> {
    for window in node_ids.windows(2) {
        if window[0] >= window[1] {
            return Err(CryptoError::TokenValidationError(
                "signatures not sorted by `node_id`".into(),
            ));
        }
    }
    Ok(())
}

/// Encode deterministic CBOR from a serializable value.
///
/// Uses ciborium with canonical encoding rules:
/// - Map keys sorted
/// - No indefinite-length encoding
/// - Smallest integer encoding
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn to_deterministic_cbor<T: serde::Serialize>(value: &T) -> CryptoResult<Vec<u8>> {
    let mut v = ciborium::value::Value::serialized(value)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    canonicalize_value_in_place(&mut v)?;

    let mut bytes = Vec::new();
    ciborium::into_writer(&v, &mut bytes)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    Ok(bytes)
}

fn canonicalize_value_in_place(v: &mut ciborium::value::Value) -> CryptoResult<()> {
    match v {
        ciborium::value::Value::Array(items) => {
            for item in items {
                canonicalize_value_in_place(item)?;
            }
        }
        ciborium::value::Value::Map(entries) => canonicalize_map(entries)?,
        ciborium::value::Value::Tag(_, boxed) => canonicalize_value_in_place(boxed)?,
        _ => {}
    }
    Ok(())
}

fn canonicalize_map(
    entries: &mut Vec<(ciborium::value::Value, ciborium::value::Value)>,
) -> CryptoResult<()> {
    use std::cmp::Ordering;

    let mut with_keys = Vec::with_capacity(entries.len());
    for (mut key, mut value) in std::mem::take(entries) {
        canonicalize_value_in_place(&mut key)?;
        canonicalize_value_in_place(&mut value)?;

        let mut key_bytes = Vec::new();
        ciborium::into_writer(&key, &mut key_bytes)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        with_keys.push((key_bytes, key, value));
    }

    with_keys.sort_by(
        |(a_bytes, _, _), (b_bytes, _, _)| match a_bytes.len().cmp(&b_bytes.len()) {
            Ordering::Equal => a_bytes.cmp(b_bytes),
            other => other,
        },
    );

    // Check for duplicates
    for window in with_keys.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(CryptoError::SerializationError(format!(
                "duplicate map key: {}",
                hex::encode(&window[0].0)
            )));
        }
    }

    *entries = with_keys
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .collect();

    Ok(())
}

/// Object that can be canonically signed.
///
/// Implementors must provide:
/// 1. Schema ID for domain separation
/// 2. Unsigned view (without signature fields)
/// 3. Deterministic CBOR serialization
pub trait Signable {
    /// Get the schema ID for this object type.
    fn schema_id(&self) -> &str;

    /// Get the canonical CBOR bytes for signing (unsigned view).
    ///
    /// This should exclude any signature-related fields.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn unsigned_cbor(&self) -> CryptoResult<Vec<u8>>;

    /// Get the full signing bytes with domain separation.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let cbor = self.unsigned_cbor()?;
        Ok(canonical_signing_bytes(self.schema_id(), &cbor))
    }
}

/// Multi-signature entry with `node_id` ordering.
#[derive(Clone, Debug)]
pub struct NodeSignature {
    /// Node identifier (for sorting).
    pub node_id: Vec<u8>,
    /// Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

impl NodeSignature {
    /// Create a new node signature.
    #[must_use]
    pub const fn new(node_id: Vec<u8>, signature: Vec<u8>) -> Self {
        Self { node_id, signature }
    }
}

/// Sort a vector of node signatures by `node_id`.
pub fn sort_node_signatures(signatures: &mut [NodeSignature]) {
    signatures.sort_by(|a, b| a.node_id.cmp(&b.node_id));
}

/// Verify that node signatures are properly sorted.
///
/// # Errors
///
/// Returns an error if not sorted lexicographically by `node_id`.
pub fn verify_node_signature_order(signatures: &[NodeSignature]) -> CryptoResult<()> {
    for window in signatures.windows(2) {
        if window[0].node_id >= window[1].node_id {
            return Err(CryptoError::TokenValidationError(
                "node signatures not sorted by node_id".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_hash_deterministic() {
        let hash1 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
        let hash2 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn schema_hash_different_schemas() {
        let hash1 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
        let hash2 = schema_hash("fcp.zone.ZoneDefinition/1.0.0");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn canonical_signing_bytes_format() {
        let cbor = b"test-cbor-bytes";
        let schema = "test.schema/1.0.0";

        let signing_bytes = canonical_signing_bytes(schema, cbor);

        assert!(signing_bytes.starts_with(SIGNING_DOMAIN));
        assert!(signing_bytes.ends_with(cbor));
        assert_eq!(
            signing_bytes.len(),
            SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + cbor.len()
        );
    }

    #[test]
    fn sort_signatures() {
        let ids: Vec<&[u8]> = vec![b"charlie", b"alice", b"bob"];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, vec![1, 2, 0]); // alice, bob, charlie
    }

    #[test]
    fn verify_signature_order_valid() {
        let ids: Vec<&[u8]> = vec![b"alice", b"bob", b"charlie"];
        assert!(verify_signature_order(&ids).is_ok());
    }

    #[test]
    fn verify_signature_order_invalid() {
        let ids: Vec<&[u8]> = vec![b"bob", b"alice", b"charlie"];
        assert!(verify_signature_order(&ids).is_err());
    }

    #[test]
    fn verify_signature_order_duplicate() {
        let ids: Vec<&[u8]> = vec![b"alice", b"alice"];
        assert!(verify_signature_order(&ids).is_err());
    }

    #[test]
    fn node_signature_sorting() {
        let mut sigs = vec![
            NodeSignature::new(b"charlie".to_vec(), vec![1]),
            NodeSignature::new(b"alice".to_vec(), vec![2]),
            NodeSignature::new(b"bob".to_vec(), vec![3]),
        ];

        sort_node_signatures(&mut sigs);

        assert_eq!(sigs[0].node_id, b"alice");
        assert_eq!(sigs[1].node_id, b"bob");
        assert_eq!(sigs[2].node_id, b"charlie");
    }

    #[test]
    fn deterministic_cbor() {
        use std::collections::BTreeMap;

        let mut map1 = BTreeMap::new();
        map1.insert("z", 1);
        map1.insert("a", 2);

        let mut map2 = BTreeMap::new();
        map2.insert("a", 2);
        map2.insert("z", 1);

        let cbor1 = to_deterministic_cbor(&map1).unwrap();
        let cbor2 = to_deterministic_cbor(&map2).unwrap();

        // BTreeMap guarantees same order regardless of insertion
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn schema_hash_golden_vector() {
        let hash = schema_hash("fcp.core.CapabilityObject/1.0.0");
        // First 8 bytes of BLAKE3("fcp.core.CapabilityObject/1.0.0")
        assert_eq!(hex::encode(hash), "28cb6f0e02d0c489");
    }

    #[test]
    fn schema_hash_is_8_bytes() {
        let hash = schema_hash("test");
        assert_eq!(hash.len(), SCHEMA_HASH_SIZE);
    }

    #[test]
    fn schema_hash_empty_string() {
        let hash = schema_hash("");
        assert_eq!(hash.len(), SCHEMA_HASH_SIZE);
        // Should still produce deterministic output
        assert_eq!(hash, schema_hash(""));
    }

    #[test]
    fn canonical_signing_bytes_deterministic() {
        let bytes1 = canonical_signing_bytes("schema", b"cbor");
        let bytes2 = canonical_signing_bytes("schema", b"cbor");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn canonical_signing_bytes_different_schemas() {
        let bytes1 = canonical_signing_bytes("schema1", b"cbor");
        let bytes2 = canonical_signing_bytes("schema2", b"cbor");
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn canonical_signing_bytes_different_cbor() {
        let bytes1 = canonical_signing_bytes("schema", b"cbor1");
        let bytes2 = canonical_signing_bytes("schema", b"cbor2");
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn canonical_signing_bytes_empty_cbor() {
        let bytes = canonical_signing_bytes("schema", b"");
        assert_eq!(bytes.len(), SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE);
    }

    #[test]
    fn sort_signatures_empty() {
        let ids: Vec<&[u8]> = vec![];
        let sorted = sort_signatures_by_node_id(&ids);
        assert!(sorted.is_empty());
    }

    #[test]
    fn sort_signatures_single() {
        let ids: Vec<&[u8]> = vec![b"only"];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, vec![0]);
    }

    #[test]
    fn verify_signature_order_empty() {
        let ids: Vec<&[u8]> = vec![];
        assert!(verify_signature_order(&ids).is_ok());
    }

    #[test]
    fn verify_signature_order_single() {
        let ids: Vec<&[u8]> = vec![b"only"];
        assert!(verify_signature_order(&ids).is_ok());
    }

    #[test]
    fn verify_node_signature_order_valid() {
        let sigs = vec![
            NodeSignature::new(b"alice".to_vec(), vec![1]),
            NodeSignature::new(b"bob".to_vec(), vec![2]),
        ];
        assert!(verify_node_signature_order(&sigs).is_ok());
    }

    #[test]
    fn verify_node_signature_order_invalid() {
        let sigs = vec![
            NodeSignature::new(b"bob".to_vec(), vec![1]),
            NodeSignature::new(b"alice".to_vec(), vec![2]),
        ];
        assert!(verify_node_signature_order(&sigs).is_err());
    }

    #[test]
    fn verify_node_signature_order_duplicate() {
        let sigs = vec![
            NodeSignature::new(b"alice".to_vec(), vec![1]),
            NodeSignature::new(b"alice".to_vec(), vec![2]),
        ];
        assert!(verify_node_signature_order(&sigs).is_err());
    }

    #[test]
    fn deterministic_cbor_hashmap_order_independent() {
        use std::collections::HashMap;

        let mut map_a = HashMap::new();
        map_a.insert("x", 1);
        map_a.insert("y", 2);

        let mut map_b = HashMap::new();
        map_b.insert("y", 2);
        map_b.insert("x", 1);

        let cbor_a = to_deterministic_cbor(&map_a).unwrap();
        let cbor_b = to_deterministic_cbor(&map_b).unwrap();
        assert_eq!(cbor_a, cbor_b);
    }

    #[test]
    fn deterministic_cbor_nested_map() {
        use std::collections::HashMap;
        let mut inner = HashMap::new();
        inner.insert("b", 2);
        inner.insert("a", 1);

        let mut outer = HashMap::new();
        outer.insert("inner", inner);

        let cbor1 = to_deterministic_cbor(&outer).unwrap();
        let cbor2 = to_deterministic_cbor(&outer).unwrap();
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn node_signature_clone() {
        let sig = NodeSignature::new(b"node".to_vec(), vec![1, 2, 3]);
        let cloned = sig.clone();
        assert_eq!(cloned.node_id, sig.node_id);
        assert_eq!(cloned.signature, sig.signature);
    }
}
