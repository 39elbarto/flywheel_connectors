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
            expected_schema_hash:
                "91cf785e23bc5e918538f21cadcc7a1356b64426b10e6a34eb4bbc92ff9def23".into(),
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
            expected_object_id: "5fc04a5e6c6b549580a78b9dd99d7f92208022873def22441f58b8df8dd84f7e"
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
        use fcp_core::{ObjectId, ObjectIdKey, ZoneId};
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
            assert!(hex::decode(&v.expected_schema_hash).is_ok(), "schema hash should be valid hex");
            assert!(hex::decode(&v.expected_cbor).is_ok(), "cbor should be valid hex");
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
            assert!(v.schema_namespace.starts_with("fcp."), "namespace should start with fcp.");
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
            assert_eq!(v.expected_object_id.len(), 64, "object_id should be 64 hex chars");
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
        assert!(v.verify().is_err(), "wrong key should produce wrong object_id");
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
        use fcp_core::{ObjectId, ObjectIdKey, ZoneId};
        use semver::Version;

        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));
        let key = ObjectIdKey::from_bytes([0u8; 32]);
        let content = b"hello";

        let zone_a: ZoneId = "z:work".parse().unwrap();
        let zone_b: ZoneId = "z:private".parse().unwrap();

        let id_a = ObjectId::new(content, &zone_a, &schema, &key);
        let id_b = ObjectId::new(content, &zone_b, &schema, &key);

        assert_ne!(id_a.to_string(), id_b.to_string(), "different zones must produce different IDs");
    }
}
