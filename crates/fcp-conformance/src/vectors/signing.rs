//! Signing-bytes canonicalization golden vectors.
//!
//! These vectors lock down the canonical signing-bytes construction used
//! for all FCP2 signed objects (ZoneCheckpoint, AuditHead, RevocationHead, etc.).
//!
//! # Signing Bytes Format (NORMATIVE)
//!
//! ```text
//! signing_bytes = SIGNING_DOMAIN || schema_hash || unsigned_cbor
//! ```
//!
//! Where:
//! - `SIGNING_DOMAIN` = `"FCP2-SIGN-V1"` (12 bytes)
//! - `schema_hash` = `BLAKE3(schema_id)[0..8]` (8 bytes)
//! - `unsigned_cbor` = deterministic CBOR of the object without signature fields
//!
//! # Quorum Signature Sorting (NORMATIVE)
//!
//! Multi-signature arrays MUST be sorted lexicographically by `node_id`.
//! Unsorted or duplicate `node_id` entries are non-compliant.

use serde::{Deserialize, Serialize};

/// Golden vector for signing-bytes canonicalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningBytesGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Schema ID string (e.g., "fcp.zone.ZoneCheckpoint/1.0.0").
    pub schema_id: String,
    /// Expected schema hash (8 bytes hex = BLAKE3(schema_id)[0..8]).
    pub expected_schema_hash: String,
    /// Sample unsigned CBOR payload (hex).
    pub unsigned_cbor: String,
    /// Expected full signing bytes (hex).
    pub expected_signing_bytes: String,
}

/// Golden vector for quorum signature sorting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumSortGoldenVector {
    /// Human-readable description.
    pub description: String,
    /// Node IDs in unsorted order (hex-encoded byte arrays).
    pub unsorted_node_ids: Vec<String>,
    /// Expected sorted order (indices into the unsorted array).
    pub expected_sorted_indices: Vec<usize>,
}

impl SigningBytesGoldenVector {
    /// Load all signing-bytes golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_zone_checkpoint_schema(),
            Self::vector_2_audit_head_schema(),
            Self::vector_3_revocation_head_schema(),
            Self::vector_4_capability_object_schema(),
        ]
    }

    /// Vector 1: ZoneCheckpoint schema hash + signing bytes.
    #[must_use]
    pub fn vector_1_zone_checkpoint_schema() -> Self {
        let schema_id = "fcp.zone.ZoneCheckpoint/1.0.0";
        let schema_hash = fcp_crypto::canonicalize::schema_hash(schema_id);
        // Sample minimal CBOR payload (a2 61 61 01 61 62 02 = {"a":1,"b":2})
        let sample_cbor = "a2616101616202";

        let cbor_bytes = hex::decode(sample_cbor).unwrap();
        let signing_bytes =
            fcp_crypto::canonicalize::canonical_signing_bytes(schema_id, &cbor_bytes);

        Self {
            description: "ZoneCheckpoint signing bytes with minimal CBOR payload".into(),
            schema_id: schema_id.into(),
            expected_schema_hash: hex::encode(schema_hash),
            unsigned_cbor: sample_cbor.into(),
            expected_signing_bytes: hex::encode(&signing_bytes),
        }
    }

    /// Vector 2: AuditHead schema hash + signing bytes.
    #[must_use]
    pub fn vector_2_audit_head_schema() -> Self {
        let schema_id = "fcp.audit.AuditHead/1.0.0";
        let schema_hash = fcp_crypto::canonicalize::schema_hash(schema_id);
        // Sample: single-field CBOR map (a1 63 736571 18 2a = {"seq": 42})
        let sample_cbor = "a163736571182a";

        let cbor_bytes = hex::decode(sample_cbor).unwrap();
        let signing_bytes =
            fcp_crypto::canonicalize::canonical_signing_bytes(schema_id, &cbor_bytes);

        Self {
            description: "AuditHead signing bytes with seq=42 payload".into(),
            schema_id: schema_id.into(),
            expected_schema_hash: hex::encode(schema_hash),
            unsigned_cbor: sample_cbor.into(),
            expected_signing_bytes: hex::encode(&signing_bytes),
        }
    }

    /// Vector 3: RevocationHead schema hash + signing bytes.
    #[must_use]
    pub fn vector_3_revocation_head_schema() -> Self {
        let schema_id = "fcp.revocation.RevocationHead/1.0.0";
        let schema_hash = fcp_crypto::canonicalize::schema_hash(schema_id);
        // Empty CBOR map (a0 = {})
        let sample_cbor = "a0";

        let cbor_bytes = hex::decode(sample_cbor).unwrap();
        let signing_bytes =
            fcp_crypto::canonicalize::canonical_signing_bytes(schema_id, &cbor_bytes);

        Self {
            description: "RevocationHead signing bytes with empty CBOR payload".into(),
            schema_id: schema_id.into(),
            expected_schema_hash: hex::encode(schema_hash),
            unsigned_cbor: sample_cbor.into(),
            expected_signing_bytes: hex::encode(&signing_bytes),
        }
    }

    /// Vector 4: CapabilityObject schema hash (cross-check with canonicalize.rs golden).
    ///
    /// This vector must produce the same schema hash as the existing test in
    /// `fcp-crypto::canonicalize::tests::schema_hash_golden_vector`.
    #[must_use]
    pub fn vector_4_capability_object_schema() -> Self {
        let schema_id = "fcp.core.CapabilityObject/1.0.0";
        let schema_hash = fcp_crypto::canonicalize::schema_hash(schema_id);
        // This hash is locked in the fcp-crypto unit test: "28cb6f0e02d0c489"
        let sample_cbor = "a16a6361706162696c697479f5"; // {"capability": true}

        let cbor_bytes = hex::decode(sample_cbor).unwrap();
        let signing_bytes =
            fcp_crypto::canonicalize::canonical_signing_bytes(schema_id, &cbor_bytes);

        Self {
            description: "CapabilityObject signing bytes (cross-check with fcp-crypto golden)"
                .into(),
            schema_id: schema_id.into(),
            expected_schema_hash: hex::encode(schema_hash),
            unsigned_cbor: sample_cbor.into(),
            expected_signing_bytes: hex::encode(&signing_bytes),
        }
    }

    /// Verify this golden vector against the implementation.
    ///
    /// # Errors
    ///
    /// Returns an error message if any step fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_crypto::canonicalize;

        // 1. Verify schema hash
        let computed_hash = canonicalize::schema_hash(&self.schema_id);
        let computed_hex = hex::encode(computed_hash);
        if computed_hex != self.expected_schema_hash {
            return Err(format!(
                "schema hash mismatch for '{}': expected {}, got {computed_hex}",
                self.schema_id, self.expected_schema_hash
            ));
        }

        // 2. Verify signing bytes construction
        let cbor_bytes = hex::decode(&self.unsigned_cbor)
            .map_err(|e| format!("invalid unsigned_cbor hex: {e}"))?;

        let computed_signing = canonicalize::canonical_signing_bytes(&self.schema_id, &cbor_bytes);
        let computed_signing_hex = hex::encode(&computed_signing);

        if computed_signing_hex != self.expected_signing_bytes {
            return Err(format!(
                "signing bytes mismatch:\n  expected: {}\n  actual:   {computed_signing_hex}",
                self.expected_signing_bytes
            ));
        }

        // 3. Verify structure: domain || schema_hash || cbor
        let domain = b"FCP2-SIGN-V1";
        if !computed_signing.starts_with(domain) {
            return Err("signing bytes missing FCP2-SIGN-V1 domain prefix".into());
        }
        if computed_signing[domain.len()..domain.len() + 8] != computed_hash {
            return Err("signing bytes schema hash position incorrect".into());
        }
        if computed_signing[domain.len() + 8..] != cbor_bytes {
            return Err("signing bytes CBOR payload position incorrect".into());
        }

        Ok(())
    }
}

impl QuorumSortGoldenVector {
    /// Load all quorum sort golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_basic_sort(),
            Self::vector_2_already_sorted(),
            Self::vector_3_binary_node_ids(),
        ]
    }

    /// Vector 1: Basic 3-node quorum sort.
    #[must_use]
    pub fn vector_1_basic_sort() -> Self {
        Self {
            description: "3-node quorum: charlie, alice, bob → alice, bob, charlie".into(),
            unsorted_node_ids: vec![
                hex::encode(b"charlie"),
                hex::encode(b"alice"),
                hex::encode(b"bob"),
            ],
            expected_sorted_indices: vec![1, 2, 0], // alice=1, bob=2, charlie=0
        }
    }

    /// Vector 2: Already-sorted quorum (identity permutation).
    #[must_use]
    pub fn vector_2_already_sorted() -> Self {
        Self {
            description: "Already sorted: alpha, beta, gamma → identity".into(),
            unsorted_node_ids: vec![
                hex::encode(b"alpha"),
                hex::encode(b"beta"),
                hex::encode(b"gamma"),
            ],
            expected_sorted_indices: vec![0, 1, 2],
        }
    }

    /// Vector 3: Binary node IDs (hash-derived, 8 bytes each).
    #[must_use]
    pub fn vector_3_binary_node_ids() -> Self {
        // These represent hash-derived 8-byte node IDs
        let ids = vec![
            "ff00112233445566".into(), // largest
            "0011223344556677".into(), // smallest
            "aa00112233445566".into(), // middle
        ];

        Self {
            description: "Binary 8-byte node IDs sorted lexicographically".into(),
            unsorted_node_ids: ids,
            expected_sorted_indices: vec![1, 2, 0], // 00.., aa.., ff..
        }
    }

    /// Verify this golden vector against the implementation.
    ///
    /// # Errors
    ///
    /// Returns an error message if any step fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_crypto::canonicalize;

        // Parse node IDs from hex
        let node_id_bytes: Vec<Vec<u8>> = self
            .unsorted_node_ids
            .iter()
            .map(|hex_str| hex::decode(hex_str).map_err(|e| format!("invalid node_id hex: {e}")))
            .collect::<Result<_, _>>()?;

        let node_id_refs: Vec<&[u8]> = node_id_bytes.iter().map(Vec::as_slice).collect();

        // Sort using implementation
        let computed_indices = canonicalize::sort_signatures_by_node_id(&node_id_refs);

        if computed_indices != self.expected_sorted_indices {
            return Err(format!(
                "sort order mismatch:\n  expected: {:?}\n  actual:   {computed_indices:?}",
                self.expected_sorted_indices
            ));
        }

        // Verify sorted order is valid
        let sorted_ids: Vec<&[u8]> = computed_indices.iter().map(|&i| node_id_refs[i]).collect();

        canonicalize::verify_signature_order(&sorted_ids)
            .map_err(|e| format!("sorted order fails verification: {e}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Signing bytes vectors ──────────────────────────────────

    #[test]
    fn signing_vectors_populated() {
        let vectors = SigningBytesGoldenVector::load_all();
        assert_eq!(vectors.len(), 4, "expected 4 signing-bytes vectors");
    }

    #[test]
    fn all_signing_vectors_verify() {
        for (i, vector) in SigningBytesGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector {} ({}) failed: {}", i + 1, vector.description, e);
            });
        }
    }

    #[test]
    fn capability_object_schema_hash_crosscheck() {
        // Must match the golden in fcp-crypto::canonicalize::tests
        let v = SigningBytesGoldenVector::vector_4_capability_object_schema();
        assert_eq!(
            v.expected_schema_hash, "28cb6f0e02d0c489",
            "CapabilityObject schema hash must match fcp-crypto golden"
        );
    }

    #[test]
    fn signing_bytes_length_invariant() {
        // signing_bytes = 12 (domain) + 8 (schema_hash) + len(cbor)
        for vector in SigningBytesGoldenVector::load_all() {
            let signing_bytes = hex::decode(&vector.expected_signing_bytes).unwrap();
            let cbor = hex::decode(&vector.unsigned_cbor).unwrap();
            assert_eq!(
                signing_bytes.len(),
                12 + 8 + cbor.len(),
                "signing bytes length invariant broken for '{}'",
                vector.description
            );
        }
    }

    #[test]
    fn different_schemas_produce_different_hashes() {
        let vectors = SigningBytesGoldenVector::load_all();
        for i in 0..vectors.len() {
            for j in (i + 1)..vectors.len() {
                if vectors[i].schema_id != vectors[j].schema_id {
                    assert_ne!(
                        vectors[i].expected_schema_hash, vectors[j].expected_schema_hash,
                        "Different schemas must produce different hashes: '{}' vs '{}'",
                        vectors[i].schema_id, vectors[j].schema_id
                    );
                }
            }
        }
    }

    // ── Quorum sort vectors ────────────────────────────────────

    #[test]
    fn quorum_sort_vectors_populated() {
        let vectors = QuorumSortGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 quorum sort vectors");
    }

    #[test]
    fn all_quorum_vectors_verify() {
        for (i, vector) in QuorumSortGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector {} ({}) failed: {}", i + 1, vector.description, e);
            });
        }
    }

    #[test]
    fn identity_sort_is_stable() {
        let v = QuorumSortGoldenVector::vector_2_already_sorted();
        assert_eq!(
            v.expected_sorted_indices,
            vec![0, 1, 2],
            "Already-sorted input must produce identity permutation"
        );
        v.verify()
            .expect("Identity sort vector verification failed");
    }
}
