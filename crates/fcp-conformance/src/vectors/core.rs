//! Core primitive golden vectors (canonical CBOR + `ObjectId` derivation).
//!
//! These vectors lock down byte-level determinism for schema hashing, canonical
//! serialization, and `ObjectId` derivation.

use serde::{Deserialize, Serialize};

/// Golden vector for canonical CBOR payloads (schema hash prefix + CBOR bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalPayloadGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Schema namespace (e.g., "fcp.test").
    pub schema_namespace: String,
    /// Schema name (e.g., `GoldenStruct`).
    pub schema_name: String,
    /// Schema version (major).
    pub schema_version_major: u64,
    /// Schema version (minor).
    pub schema_version_minor: u64,
    /// Schema version (patch).
    pub schema_version_patch: u64,
    /// Payload: id field.
    pub id: u64,
    /// Payload: name field.
    pub name: String,
    /// Payload: active field.
    pub active: bool,
    /// Expected schema hash prefix (hex, 32 bytes).
    pub expected_schema_hash: String,
    /// Expected canonical CBOR bytes (hex).
    pub expected_cbor: String,
}

impl CanonicalPayloadGoldenVector {
    /// Load all canonical CBOR golden vectors.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: Vec allocation
    pub fn load_all() -> Vec<Self> {
        vec![Self {
            description: "Canonical CBOR payload (GoldenStruct v1.0.0)".into(),
            schema_namespace: "fcp.test".into(),
            schema_name: "GoldenStruct".into(),
            schema_version_major: 1,
            schema_version_minor: 0,
            schema_version_patch: 0,
            id: 12_345,
            name: "test".into(),
            active: true,
            // Length-prefixed BLAKE3 over (SCHEMA_HASH_DOMAIN_SEPARATOR ||
            // len(ns)||ns || len(name)||name || len(version)||version) where each
            // length is u64-LE. Updated 2026-04-26 (REVIEW-A9 / mzi9x) to fix
            // SchemaId separator-collision; the prior raw-concat hash aliased
            // distinct schema tuples.
            expected_schema_hash:
                "824698784c7724fe18470ecdd2c2199abb4632c25998c9d143adab875e8ca5d7".into(),
            expected_cbor: "a3626964193039646e616d65647465737466616374697665f5".into(),
        }]
    }

    /// Verify the golden vector against the implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the vector does not match the implementation.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_cbor::{CanonicalSerializer, SchemaId};
        use semver::Version;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct GoldenStruct {
            id: u64,
            name: String,
            active: bool,
        }

        let schema = SchemaId::new(
            &self.schema_namespace,
            &self.schema_name,
            Version::new(
                self.schema_version_major,
                self.schema_version_minor,
                self.schema_version_patch,
            ),
        );

        let value = GoldenStruct {
            id: self.id,
            name: self.name.clone(),
            active: self.active,
        };

        let payload = CanonicalSerializer::serialize(&value, &schema)
            .map_err(|e| format!("serialize failed: {e}"))?;

        let expected_schema_hash = hex::decode(&self.expected_schema_hash)
            .map_err(|e| format!("invalid expected_schema_hash hex: {e}"))?;
        let expected_cbor = hex::decode(&self.expected_cbor)
            .map_err(|e| format!("invalid expected_cbor hex: {e}"))?;

        let mut expected_payload =
            Vec::with_capacity(expected_schema_hash.len() + expected_cbor.len());
        expected_payload.extend_from_slice(&expected_schema_hash);
        expected_payload.extend_from_slice(&expected_cbor);

        if payload != expected_payload {
            return Err("canonical payload mismatch".into());
        }

        if payload.len() < expected_schema_hash.len() {
            return Err("payload shorter than schema hash".into());
        }

        if payload[..expected_schema_hash.len()] != expected_schema_hash {
            return Err("schema hash prefix mismatch".into());
        }

        if payload[expected_schema_hash.len()..] != expected_cbor {
            return Err("canonical CBOR bytes mismatch".into());
        }

        Ok(())
    }
}

/// Golden vector for keyed `ObjectId` derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectIdGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Zone identifier (e.g., "z:work").
    pub zone_id: String,
    /// Schema namespace.
    pub schema_namespace: String,
    /// Schema name.
    pub schema_name: String,
    /// Schema version (major).
    pub schema_version_major: u64,
    /// Schema version (minor).
    pub schema_version_minor: u64,
    /// Schema version (patch).
    pub schema_version_patch: u64,
    /// `ObjectId` key (hex, 32 bytes).
    pub key: String,
    /// Content bytes (hex).
    pub content: String,
    /// Expected `ObjectId` (hex, 32 bytes).
    pub expected_object_id: String,
}

impl ObjectIdGoldenVector {
    /// Load all `ObjectId` golden vectors.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: Vec allocation
    pub fn load_all() -> Vec<Self> {
        vec![Self {
            description: "Keyed ObjectId derivation (CapabilityObject)".into(),
            zone_id: "z:work".into(),
            schema_namespace: "fcp.core".into(),
            schema_name: "CapabilityObject".into(),
            schema_version_major: 1,
            schema_version_minor: 0,
            schema_version_patch: 0,
            key: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            content: "68656c6c6f".into(),
            // Updated 2026-04-26 (REVIEW-A9 / mzi9x) alongside SchemaId::hash
            // length-prefixing fix; ObjectId derivation feeds the schema hash.
            expected_object_id: "6d766e3dd7615531c490254cf35644c0c21bb734cbaf26938a8edcf2da6ca36a"
                .into(),
        }]
    }

    /// Verify the golden vector against the implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the golden vector fails verification.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_cbor::SchemaId;
        use fcp_prelude::{ObjectId, ObjectIdKey, ZoneId};
        use semver::Version;

        let zone: ZoneId = self
            .zone_id
            .parse()
            .map_err(|e| format!("invalid zone_id: {e}"))?;
        let schema = SchemaId::new(
            &self.schema_namespace,
            &self.schema_name,
            Version::new(
                self.schema_version_major,
                self.schema_version_minor,
                self.schema_version_patch,
            ),
        );

        let key_bytes = hex::decode(&self.key).map_err(|e| format!("invalid key hex: {e}"))?;
        let content_bytes =
            hex::decode(&self.content).map_err(|e| format!("invalid content hex: {e}"))?;

        if key_bytes.len() != 32 {
            return Err("ObjectId key must be 32 bytes".into());
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let key = ObjectIdKey::from_bytes(key_arr);

        let object_id = ObjectId::new(&content_bytes, &zone, &schema, &key);
        if object_id.to_string() != self.expected_object_id {
            return Err("object_id mismatch".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vectors_populated() {
        let vectors = CanonicalPayloadGoldenVector::load_all();
        assert!(!vectors.is_empty(), "vectors should be populated");
    }

    #[test]
    fn canonical_vectors_match() {
        for vector in CanonicalPayloadGoldenVector::load_all() {
            vector.verify().expect("canonical payload should match");
        }
    }

    #[test]
    fn object_id_vectors_populated() {
        let vectors = ObjectIdGoldenVector::load_all();
        assert!(!vectors.is_empty(), "vectors should be populated");
    }

    #[test]
    fn object_id_vectors_match() {
        for vector in ObjectIdGoldenVector::load_all() {
            vector.verify().expect("object id should match");
        }
    }

    // ── CanonicalPayloadGoldenVector field tests ─────────────

    #[test]
    fn canonical_vector_has_valid_hex_fields() {
        for v in CanonicalPayloadGoldenVector::load_all() {
            assert!(
                hex::decode(&v.expected_schema_hash).is_ok(),
                "schema hash should be valid hex"
            );
            assert!(
                hex::decode(&v.expected_cbor).is_ok(),
                "cbor should be valid hex"
            );
        }
    }

    #[test]
    fn canonical_vector_schema_hash_is_32_bytes() {
        for v in CanonicalPayloadGoldenVector::load_all() {
            let bytes = hex::decode(&v.expected_schema_hash).unwrap();
            assert_eq!(bytes.len(), 32, "schema hash should be 32 bytes");
        }
    }

    #[test]
    fn canonical_vector_description_not_empty() {
        for v in CanonicalPayloadGoldenVector::load_all() {
            assert!(!v.description.is_empty());
        }
    }

    #[test]
    fn canonical_vector_schema_namespace_prefixed() {
        for v in CanonicalPayloadGoldenVector::load_all() {
            assert!(
                v.schema_namespace.starts_with("fcp."),
                "namespace should start with fcp."
            );
        }
    }

    #[test]
    fn canonical_vector_schema_name_not_empty() {
        for v in CanonicalPayloadGoldenVector::load_all() {
            assert!(!v.schema_name.is_empty());
        }
    }

    #[test]
    fn canonical_vector_verify_bad_schema_hash() {
        let mut v = CanonicalPayloadGoldenVector::load_all().remove(0);
        v.expected_schema_hash = "ff".repeat(32);
        assert!(v.verify().is_err(), "tampered schema hash should fail");
    }

    #[test]
    fn canonical_vector_verify_bad_cbor() {
        let mut v = CanonicalPayloadGoldenVector::load_all().remove(0);
        v.expected_cbor = "deadbeef".to_string();
        assert!(v.verify().is_err(), "tampered cbor should fail");
    }

    #[test]
    fn canonical_vector_verify_invalid_hex() {
        let mut v = CanonicalPayloadGoldenVector::load_all().remove(0);
        v.expected_schema_hash = "not_valid_hex".to_string();
        assert!(v.verify().is_err(), "invalid hex should fail");
    }

    #[test]
    fn canonical_vector_verify_invalid_cbor_hex() {
        let mut v = CanonicalPayloadGoldenVector::load_all().remove(0);
        v.expected_cbor = "zzzz".to_string();
        assert!(v.verify().is_err(), "invalid cbor hex should fail");
    }

    #[test]
    fn canonical_vector_serde_roundtrip() {
        let v = CanonicalPayloadGoldenVector::load_all().remove(0);
        let json = serde_json::to_string(&v).unwrap();
        let parsed: CanonicalPayloadGoldenVector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.description, v.description);
        assert_eq!(parsed.expected_cbor, v.expected_cbor);
        parsed.verify().expect("deserialized vector should verify");
    }

    // ── ObjectIdGoldenVector field tests ─────────────────────

    #[test]
    fn object_id_vector_key_is_32_bytes() {
        for v in ObjectIdGoldenVector::load_all() {
            let bytes = hex::decode(&v.key).unwrap();
            assert_eq!(bytes.len(), 32, "key should be 32 bytes");
        }
    }

    #[test]
    fn object_id_vector_expected_id_is_32_bytes() {
        for v in ObjectIdGoldenVector::load_all() {
            assert_eq!(
                v.expected_object_id.len(),
                64,
                "object_id should be 64 hex chars"
            );
        }
    }

    #[test]
    fn object_id_vector_zone_id_valid() {
        for v in ObjectIdGoldenVector::load_all() {
            assert!(v.zone_id.starts_with("z:"), "zone_id should start with z:");
        }
    }

    #[test]
    fn object_id_verify_bad_key() {
        let mut v = ObjectIdGoldenVector::load_all().remove(0);
        v.key = "ff".repeat(32);
        assert!(
            v.verify().is_err(),
            "wrong key should produce wrong object_id"
        );
    }

    #[test]
    fn object_id_verify_bad_content() {
        let mut v = ObjectIdGoldenVector::load_all().remove(0);
        v.content = "ff".to_string();
        assert!(v.verify().is_err(), "different content should fail");
    }

    #[test]
    fn object_id_verify_invalid_key_hex() {
        let mut v = ObjectIdGoldenVector::load_all().remove(0);
        v.key = "not_hex".to_string();
        assert!(v.verify().is_err(), "invalid key hex should fail");
    }

    #[test]
    fn object_id_verify_wrong_key_length() {
        let mut v = ObjectIdGoldenVector::load_all().remove(0);
        v.key = "aabb".to_string(); // 2 bytes, not 32
        assert!(v.verify().is_err(), "wrong key length should fail");
    }

    #[test]
    fn object_id_verify_invalid_zone() {
        let mut v = ObjectIdGoldenVector::load_all().remove(0);
        v.zone_id = "invalid-zone".to_string();
        assert!(v.verify().is_err(), "invalid zone_id should fail");
    }

    #[test]
    fn object_id_serde_roundtrip() {
        let v = ObjectIdGoldenVector::load_all().remove(0);
        let json = serde_json::to_string(&v).unwrap();
        let parsed: ObjectIdGoldenVector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.expected_object_id, v.expected_object_id);
        parsed.verify().expect("deserialized vector should verify");
    }

    #[test]
    fn object_id_different_zones_different_ids() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::{ObjectId, ObjectIdKey, ZoneId};
        use semver::Version;

        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let content = b"hello";

        let zone_a: ZoneId = "z:work".parse().unwrap();
        let zone_b: ZoneId = "z:private".parse().unwrap();

        let id_a = ObjectId::new(content, &zone_a, &schema, &key);
        let id_b = ObjectId::new(content, &zone_b, &schema, &key);

        assert_ne!(
            id_a.to_string(),
            id_b.to_string(),
            "different zones must produce different IDs"
        );
    }

    // ── Spec-derived determinism matrix (FCP V3 §6) ──────────
    //
    // These tests lock down the normative MUST clauses for
    // canonical serialization and keyed ObjectId derivation.
    // Each test captures exactly one metamorphic relation;
    // failures should narrow to a single violated invariant.

    use fcp_cbor::{CanonicalSerializer, SchemaId};
    use fcp_prelude::{ObjectId, ObjectIdKey, ZoneId};
    use semver::Version;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct SampleStruct {
        id: u64,
        name: String,
        active: bool,
    }

    fn sample() -> SampleStruct {
        SampleStruct {
            id: 12_345,
            name: "test".into(),
            active: true,
        }
    }

    fn schema_v1() -> SchemaId {
        SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0))
    }

    fn all_canonical_zones() -> Vec<ZoneId> {
        vec![
            ZoneId::owner(),
            ZoneId::private(),
            ZoneId::work(),
            ZoneId::community(),
            ZoneId::public(),
        ]
    }

    // ── Canonical serializer determinism ─────────────────────

    #[test]
    fn canonical_serializer_is_deterministic_across_invocations() {
        let schema = schema_v1();
        let value = sample();
        let a = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let b = CanonicalSerializer::serialize(&value, &schema).unwrap();
        assert_eq!(a, b, "repeated serialization must produce identical bytes");
    }

    #[test]
    fn schema_version_bump_changes_schema_hash_prefix() {
        let value = sample();
        let v1 = schema_v1();
        let v2 = SchemaId::new("fcp.test", "GoldenStruct", Version::new(2, 0, 0));
        let a = CanonicalSerializer::serialize(&value, &v1).unwrap();
        let b = CanonicalSerializer::serialize(&value, &v2).unwrap();
        assert_ne!(
            &a[..32],
            &b[..32],
            "major version change MUST produce a different schema hash"
        );
    }

    #[test]
    fn schema_namespace_change_changes_schema_hash_prefix() {
        let value = sample();
        let a_schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let b_schema = SchemaId::new("fcp.other", "GoldenStruct", Version::new(1, 0, 0));
        let a = CanonicalSerializer::serialize(&value, &a_schema).unwrap();
        let b = CanonicalSerializer::serialize(&value, &b_schema).unwrap();
        assert_ne!(&a[..32], &b[..32]);
    }

    #[test]
    fn schema_name_change_changes_schema_hash_prefix() {
        let value = sample();
        let a_schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let b_schema = SchemaId::new("fcp.test", "OtherStruct", Version::new(1, 0, 0));
        let a = CanonicalSerializer::serialize(&value, &a_schema).unwrap();
        let b = CanonicalSerializer::serialize(&value, &b_schema).unwrap();
        assert_ne!(&a[..32], &b[..32]);
    }

    #[test]
    fn schema_patch_bump_changes_schema_hash_prefix() {
        let value = sample();
        let a_schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let b_schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 1));
        let a = CanonicalSerializer::serialize(&value, &a_schema).unwrap();
        let b = CanonicalSerializer::serialize(&value, &b_schema).unwrap();
        assert_ne!(
            &a[..32],
            &b[..32],
            "any version component change MUST change the schema hash"
        );
    }

    #[test]
    fn canonical_payload_layout_is_schema_hash_then_cbor() {
        // Layout MUST be: SCHEMA_HASH_LEN bytes || canonical CBOR bytes
        let schema = schema_v1();
        let value = sample();
        let payload = CanonicalSerializer::serialize(&value, &schema).unwrap();
        assert!(
            payload.len() >= 32,
            "payload must contain schema hash prefix"
        );
        // CBOR bytes come after the 32-byte hash
        let cbor = &payload[32..];
        assert!(!cbor.is_empty(), "payload must contain CBOR body");
    }

    // ── ObjectId determinism matrix ──────────────────────────

    #[test]
    fn object_id_all_five_canonical_zones_produce_distinct_ids() {
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let content = b"determinism";
        let ids: Vec<String> = all_canonical_zones()
            .iter()
            .map(|z| ObjectId::new(content, z, &schema, &key).to_string())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            5,
            "the 5 canonical zones must derive 5 distinct ObjectIds for identical content"
        );
    }

    #[test]
    fn object_id_key_change_changes_id() {
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let content = b"hello";
        let id_a = ObjectId::new(
            content,
            &zone,
            &schema,
            &ObjectIdKey::from_bytes([0x00; 32]),
        );
        let id_b = ObjectId::new(
            content,
            &zone,
            &schema,
            &ObjectIdKey::from_bytes([0xFF; 32]),
        );
        assert_ne!(
            id_a.to_string(),
            id_b.to_string(),
            "different ObjectIdKey MUST produce different ObjectId"
        );
    }

    #[test]
    fn object_id_schema_change_changes_id() {
        let zone = ZoneId::work();
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let content = b"hello";
        let s_a = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let s_b = SchemaId::new("fcp.core", "OtherObject", Version::new(1, 0, 0));
        let id_a = ObjectId::new(content, &zone, &s_a, &key);
        let id_b = ObjectId::new(content, &zone, &s_b, &key);
        assert_ne!(
            id_a.to_string(),
            id_b.to_string(),
            "different schema MUST produce different ObjectId"
        );
    }

    #[test]
    fn object_id_content_change_changes_id() {
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let id_a = ObjectId::new(b"hello", &zone, &schema, &key);
        let id_b = ObjectId::new(b"hellp", &zone, &schema, &key);
        assert_ne!(
            id_a.to_string(),
            id_b.to_string(),
            "single-bit content change MUST produce a different ObjectId"
        );
    }

    #[test]
    fn object_id_empty_content_is_valid_and_deterministic() {
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let a = ObjectId::new(&[], &zone, &schema, &key);
        let b = ObjectId::new(&[], &zone, &schema, &key);
        assert_eq!(a.to_string(), b.to_string());
        assert_eq!(a.to_string().len(), 64);
    }

    #[test]
    fn object_id_large_content_is_stable_across_invocations() {
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0x42; 32]);
        let content = vec![0xABu8; 1_048_576]; // 1 MiB
        let a = ObjectId::new(&content, &zone, &schema, &key);
        let b = ObjectId::new(&content, &zone, &schema, &key);
        assert_eq!(
            a.to_string(),
            b.to_string(),
            "large content must derive deterministically"
        );
    }

    #[test]
    fn object_id_is_32_bytes_64_hex_chars_lowercase() {
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0x01; 32]);
        let id = ObjectId::new(b"x", &zone, &schema, &key);
        let s = id.to_string();
        assert_eq!(s.len(), 64, "ObjectId hex must be 64 chars (32 bytes)");
        assert!(
            s.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "ObjectId hex must be lowercase ascii hex"
        );
    }

    #[test]
    fn object_id_zero_key_still_deterministic() {
        // Regression: all-zero key is a degenerate but valid input.
        // It MUST still produce a deterministic, 32-byte id.
        let zone = ZoneId::private();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let a = ObjectId::new(b"determinism", &zone, &schema, &key);
        let b = ObjectId::new(b"determinism", &zone, &schema, &key);
        assert_eq!(a.to_string(), b.to_string());
    }

    #[test]
    fn object_id_bit_flip_in_key_changes_id() {
        // Stronger key-separation: flipping a single bit in the 32-byte
        // ObjectIdKey MUST produce a different ObjectId.
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let k1 = [0x42u8; 32];
        let mut k2 = k1;
        k2[17] ^= 0x01;
        let id_a = ObjectId::new(b"hello", &zone, &schema, &ObjectIdKey::from_bytes(k1));
        let id_b = ObjectId::new(b"hello", &zone, &schema, &ObjectIdKey::from_bytes(k2));
        assert_ne!(id_a.to_string(), id_b.to_string());
    }

    // ── ZoneId canonical surface ─────────────────────────────

    #[test]
    fn zone_id_canonical_strings_match_constants() {
        assert_eq!(ZoneId::owner().as_str(), "z:owner");
        assert_eq!(ZoneId::private().as_str(), "z:private");
        assert_eq!(ZoneId::work().as_str(), "z:work");
        assert_eq!(ZoneId::community().as_str(), "z:community");
        assert_eq!(ZoneId::public().as_str(), "z:public");
    }

    #[test]
    fn zone_id_tailscale_tag_roundtrip_for_all_canonical_zones() {
        for zone in all_canonical_zones()
            .into_iter()
            .chain(["z:project:foo".parse().unwrap()])
        {
            let tag = zone.to_tailscale_tag();
            assert!(
                tag.starts_with("tag:fcp-"),
                "tailscale tag must have 'tag:fcp-' prefix, got {tag}"
            );
            let back = ZoneId::from_tailscale_tag(&tag)
                .unwrap_or_else(|e| panic!("roundtrip failed for {zone:?}: {e:?}"));
            assert_eq!(
                zone.as_str(),
                back.as_str(),
                "roundtrip lost canonical name"
            );
        }
    }

    #[test]
    fn project_zone_uses_project_tag_family() {
        let zone: ZoneId = "z:project:foo".parse().expect("valid project zone");
        assert_eq!(zone.to_tailscale_tag(), "tag:fcp-proj-foo");

        let back =
            ZoneId::from_tailscale_tag("tag:fcp-proj-foo").expect("project tag should decode");
        assert_eq!(back.as_str(), "z:project:foo");
    }

    #[test]
    fn abbreviated_project_zone_alias_is_rejected() {
        assert!(
            "z:proj-foo".parse::<ZoneId>().is_err(),
            "z:proj-* would collide with the reserved tag:fcp-proj-* project-zone family"
        );
    }

    #[test]
    fn project_zone_names_are_tailscale_tag_safe() {
        for zone in ["z:project:foo_bar", "z:project:foo:bar"] {
            assert!(
                zone.parse::<ZoneId>().is_err(),
                "{zone} would flatten to an ambiguous Tailscale tag"
            );
        }
    }

    #[test]
    fn zone_id_hash_is_deterministic() {
        let z = ZoneId::work();
        let h1 = z.hash();
        let h2 = z.hash();
        assert_eq!(h1, h2, "ZoneId hash must be deterministic");
    }

    #[test]
    fn zone_id_hash_distinguishes_all_canonical_zones() {
        let hashes: Vec<_> = all_canonical_zones().iter().map(ZoneId::hash).collect();
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique.len(),
            5,
            "canonical zones must produce 5 distinct hashes"
        );
    }

    #[test]
    fn zone_id_hash_output_is_32_bytes() {
        let bytes = ZoneId::work().hash();
        assert_eq!(
            bytes.as_ref().len(),
            32,
            "ZoneIdHash must be 32 bytes (BLAKE3 output)"
        );
    }

    #[test]
    fn zone_id_tailscale_tag_rejects_non_fcp_prefix() {
        let bad = ["", "fcp-work", "tag:other-work", "tag:fcp", "work"];
        for tag in bad {
            assert!(
                ZoneId::from_tailscale_tag(tag).is_err(),
                "tag {tag:?} should be rejected"
            );
        }
    }

    #[test]
    fn object_id_produced_by_new_is_independent_of_call_order() {
        // Calling ObjectId::new on inputs in any order (A then B, B then A)
        // MUST produce the same hashes — i.e., no hidden global state.
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0x11; 32]);

        let first_a = ObjectId::new(b"alpha", &zone, &schema, &key);
        let first_b = ObjectId::new(b"beta", &zone, &schema, &key);

        let second_b = ObjectId::new(b"beta", &zone, &schema, &key);
        let second_a = ObjectId::new(b"alpha", &zone, &schema, &key);

        assert_eq!(first_a.to_string(), second_a.to_string());
        assert_eq!(first_b.to_string(), second_b.to_string());
    }
}
