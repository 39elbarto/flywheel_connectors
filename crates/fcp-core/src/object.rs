//! Mesh object primitives: `ObjectId`, `ObjectHeader`, and storage metadata.
//!
//! This module implements the foundational primitives from `FCP_Specification_V2.md` §3.

use std::fmt;

use fcp_cbor::{SchemaId, SerializationError};
use serde::{Deserialize, Serialize};

use crate::{Provenance, ZoneId};

/// Content-addressed identifier (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)] // Use transparent to delegate to the inner array via hex_or_bytes
pub struct ObjectId(#[serde(with = "crate::util::hex_or_bytes")] [u8; 32]);

impl ObjectId {
    /// Construct an `ObjectId` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create `ObjectId` from content, zone, and schema (NORMATIVE for security objects).
    #[must_use]
    pub fn new(content: &[u8], zone: &ZoneId, schema: &SchemaId, key: &ObjectIdKey) -> Self {
        let mut h = blake3::Hasher::new_keyed(&key.0);
        h.update(b"FCP2-OBJECT-V2");
        h.update(zone.as_bytes());
        h.update(schema.hash().as_bytes());
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Unscoped content hash (NON-NORMATIVE; MUST NOT be used for security objects).
    #[must_use]
    pub fn from_unscoped_bytes(content: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-CONTENT-V2");
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Create a test `ObjectId` from a string identifier.
    ///
    /// This is a convenience method for tests only.
    #[cfg(test)]
    #[must_use]
    pub fn test_id(name: &str) -> Self {
        Self::from_unscoped_bytes(name.as_bytes())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectId").field(&self.to_string()).finish()
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for ObjectId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Secret per-zone object-id key (NORMATIVE).
///
/// This key is distributed to zone members via `ZoneKeyManifest` (NORMATIVE) and remains stable
/// across routine zone key rotations. It provides privacy against dictionary attacks on
/// low-entropy objects.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectIdKey([u8; 32]);

impl ObjectIdKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ObjectIdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectIdKey")
            .field(&"[redacted; 32 bytes]")
            .finish()
    }
}

/// Typed device selector for placement policies (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceSelector {
    Tag(String),
    Class(String),
    NodeId(u64),
    Zone(ZoneId),
    HasCapability(String),
}

/// Object placement policy (NORMATIVE when used).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPlacementPolicy {
    pub min_nodes: u8,
    pub max_node_fraction_bps: u16,
    #[serde(default)]
    pub preferred_devices: Vec<DeviceSelector>,
    #[serde(default)]
    pub excluded_devices: Vec<DeviceSelector>,
    pub target_coverage_bps: u32,
    /// Minimum distinct source nodes required for reconstruction (diversity enforcement).
    /// When set, objects MUST have symbols from at least this many distinct nodes
    /// before reconstruction is permitted. Default is 0 (no diversity requirement).
    #[serde(default)]
    pub min_source_diversity: u8,
}

/// Universal object header (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHeader {
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub created_at: u64,
    pub provenance: Provenance,
    #[serde(default)]
    pub refs: Vec<ObjectId>,
    #[serde(default)]
    pub foreign_refs: Vec<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<ObjectPlacementPolicy>,
}

/// Retention class for garbage collection (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionClass {
    Pinned,
    Lease { expires_at: u64 },
    Ephemeral,
}

/// Node-local storage metadata (NOT content-addressed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMeta {
    pub retention: RetentionClass,
}

/// Stored object record (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    pub object_id: ObjectId,
    pub header: ObjectHeader,
    /// Canonical CBOR body (schema-prefixed).
    pub body: Vec<u8>,
    /// Node-local storage policy.
    pub storage: StorageMeta,
}

impl StoredObject {
    /// Canonical bytes used for `ObjectId` derivation (NORMATIVE).
    ///
    /// Format: `b"FCP2-OBJECT-V1" || canonical_cbor(header) || body`.
    ///
    /// # Errors
    /// Returns a serialization error if the header cannot be encoded canonically or if the
    /// resulting bytes exceed `fcp_cbor::MAX_CANONICAL_OBJECT_BYTES`.
    pub fn canonical_bytes(
        header: &ObjectHeader,
        body: &[u8],
    ) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FCP2-OBJECT-V1");
        out.extend_from_slice(&fcp_cbor::to_canonical_cbor(header)?);
        out.extend_from_slice(body);

        if out.len() > fcp_cbor::MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: out.len(),
                max: fcp_cbor::MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        Ok(out)
    }

    /// Derive the object id for a stored object (NORMATIVE).
    ///
    /// # Errors
    /// Returns a serialization error if canonical bytes cannot be constructed.
    pub fn derive_id(
        header: &ObjectHeader,
        body: &[u8],
        key: &ObjectIdKey,
    ) -> Result<ObjectId, SerializationError> {
        let content = Self::canonical_bytes(header, body)?;
        Ok(ObjectId::new(
            &content,
            &header.zone_id,
            &header.schema,
            key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_golden_vector_smoke() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));

        let object_id = ObjectId::new(b"hello", &zone, &schema, &key);

        // Golden vector: keyed BLAKE3 with domain separation
        // Input: key=[0;32], zone="z:work", schema="fcp.core/CapabilityObject@1.0.0", content=b"hello"
        // Hash: blake3_keyed(key, "FCP2-OBJECT-V2" || zone_bytes || schema_hash || content)
        assert_eq!(
            object_id.to_string(),
            "5fc04a5e6c6b549580a78b9dd99d7f92208022873def22441f58b8df8dd84f7e"
        );
    }

    #[test]
    fn object_id_from_bytes_roundtrip() {
        let bytes = [42_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        assert_eq!(object_id.as_bytes(), &bytes);
    }

    #[test]
    fn object_id_display_is_hex() {
        let bytes = [0xab_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        assert_eq!(object_id.to_string(), "ab".repeat(32));
    }

    #[test]
    fn object_id_debug_shows_hex() {
        let bytes = [0xff_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        let debug = format!("{object_id:?}");
        assert!(debug.contains("ObjectId"));
        assert!(debug.contains(&"ff".repeat(32)));
    }

    #[test]
    fn object_id_as_ref_slice() {
        let bytes = [1_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        let slice: &[u8] = object_id.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    fn object_id_unscoped_deterministic() {
        let content = b"test content";
        let id1 = ObjectId::from_unscoped_bytes(content);
        let id2 = ObjectId::from_unscoped_bytes(content);
        assert_eq!(id1, id2);
    }

    #[test]
    fn object_id_unscoped_differs_by_content() {
        let id1 = ObjectId::from_unscoped_bytes(b"content a");
        let id2 = ObjectId::from_unscoped_bytes(b"content b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_keyed_differs_by_key() {
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let content = b"same content";

        let key1 = ObjectIdKey::from_bytes([1_u8; 32]);
        let key2 = ObjectIdKey::from_bytes([2_u8; 32]);

        let id1 = ObjectId::new(content, &zone, &schema, &key1);
        let id2 = ObjectId::new(content, &zone, &schema, &key2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_keyed_differs_by_zone() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let content = b"same content";

        let zone1: ZoneId = "z:work".parse().unwrap();
        let zone2: ZoneId = "z:private".parse().unwrap();

        let id1 = ObjectId::new(content, &zone1, &schema, &key);
        let id2 = ObjectId::new(content, &zone2, &schema, &key);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_keyed_differs_by_schema() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let content = b"same content";

        let schema1 = SchemaId::new("fcp.test", "TestA", Version::new(1, 0, 0));
        let schema2 = SchemaId::new("fcp.test", "TestB", Version::new(1, 0, 0));

        let id1 = ObjectId::new(content, &zone, &schema1, &key);
        let id2 = ObjectId::new(content, &zone, &schema2, &key);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_equality_and_hash() {
        use std::collections::HashSet;

        let bytes = [7_u8; 32];
        let id1 = ObjectId::from_bytes(bytes);
        let id2 = ObjectId::from_bytes(bytes);

        assert_eq!(id1, id2);

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectIdKey Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_key_from_bytes_roundtrip() {
        let bytes = [99_u8; 32];
        let key = ObjectIdKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn object_id_key_debug_redacts() {
        let key = ObjectIdKey::from_bytes([0xde_u8; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("ObjectIdKey"));
        assert!(debug.contains("redacted"));
        // MUST NOT contain actual key bytes
        assert!(!debug.contains("de"));
    }

    #[test]
    fn object_id_key_equality_and_hash() {
        use std::collections::HashSet;

        let bytes = [42_u8; 32];
        let key1 = ObjectIdKey::from_bytes(bytes);
        let key2 = ObjectIdKey::from_bytes(bytes);

        assert_eq!(key1, key2);

        let mut set = HashSet::new();
        set.insert(key1);
        assert!(set.contains(&key2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeviceSelector Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn device_selector_serialization() {
        let tag = DeviceSelector::Tag("gpu".into());
        let json = serde_json::to_string(&tag).unwrap();
        assert!(json.contains("Tag"));
        assert!(json.contains("gpu"));

        let class = DeviceSelector::Class("high-mem".into());
        let json = serde_json::to_string(&class).unwrap();
        assert!(json.contains("Class"));

        let node = DeviceSelector::NodeId(12345);
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("NodeId"));
        assert!(json.contains("12345"));

        let zone = DeviceSelector::Zone(ZoneId::work());
        let json = serde_json::to_string(&zone).unwrap();
        assert!(json.contains("Zone"));
        assert!(json.contains("z:work"));

        let cap = DeviceSelector::HasCapability("gpu.compute".into());
        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("HasCapability"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectPlacementPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_placement_policy_serialization_roundtrip() {
        let policy = ObjectPlacementPolicy {
            min_nodes: 3,
            max_node_fraction_bps: 5000, // 50%
            preferred_devices: vec![DeviceSelector::Tag("ssd".into())],
            excluded_devices: vec![DeviceSelector::Class("low-mem".into())],
            target_coverage_bps: 10000, // 100%
            min_source_diversity: 2,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.min_nodes, 3);
        assert_eq!(deserialized.max_node_fraction_bps, 5000);
        assert_eq!(deserialized.target_coverage_bps, 10000);
        assert_eq!(deserialized.preferred_devices.len(), 1);
        assert_eq!(deserialized.excluded_devices.len(), 1);
        assert_eq!(deserialized.min_source_diversity, 2);
    }

    #[test]
    fn object_placement_policy_default_vectors() {
        let minimal = ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
            min_source_diversity: 0,
        };

        let json = serde_json::to_string(&minimal).unwrap();
        let deserialized: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();
        assert!(deserialized.preferred_devices.is_empty());
        assert!(deserialized.excluded_devices.is_empty());
        assert_eq!(deserialized.min_source_diversity, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectHeader Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_header_serialization_roundtrip() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.core", "TestObject", Version::new(1, 2, 3)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![ObjectId::from_bytes([1_u8; 32])],
            foreign_refs: vec![],
            ttl_secs: Some(3600),
            placement: None,
        };

        let json = serde_json::to_string(&header).unwrap();
        let deserialized: ObjectHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.zone_id.as_str(), "z:work");
        assert_eq!(deserialized.created_at, 1_700_000_000);
        assert_eq!(deserialized.refs.len(), 1);
        assert_eq!(deserialized.ttl_secs, Some(3600));
    }

    #[test]
    fn object_header_optional_fields_omitted() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.core", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::public(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::public()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let json = serde_json::to_string(&header).unwrap();
        // ttl_secs should be omitted when None
        assert!(!json.contains("ttl_secs"));
        // placement should be omitted when None
        assert!(!json.contains("placement"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RetentionClass Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retention_class_pinned() {
        let retention = RetentionClass::Pinned;
        let json = serde_json::to_string(&retention).unwrap();
        assert!(json.contains("Pinned"));

        let deserialized: RetentionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, RetentionClass::Pinned);
    }

    #[test]
    fn retention_class_lease() {
        let retention = RetentionClass::Lease {
            expires_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&retention).unwrap();
        assert!(json.contains("Lease"));
        assert!(json.contains("1700000000"));

        let deserialized: RetentionClass = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized,
            RetentionClass::Lease {
                expires_at: 1_700_000_000
            }
        ));
    }

    #[test]
    fn retention_class_ephemeral() {
        let retention = RetentionClass::Ephemeral;
        let json = serde_json::to_string(&retention).unwrap();
        assert!(json.contains("Ephemeral"));

        let deserialized: RetentionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, RetentionClass::Ephemeral);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StoredObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn stored_object_canonical_bytes_format() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"test body content";

        let canonical = StoredObject::canonical_bytes(&header, body).unwrap();

        // Must start with domain separator
        assert!(canonical.starts_with(b"FCP2-OBJECT-V1"));
        // Must end with body
        assert!(canonical.ends_with(body));
    }

    #[test]
    fn stored_object_derive_id_deterministic() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"test body";
        let key = ObjectIdKey::from_bytes([0_u8; 32]);

        let id1 = StoredObject::derive_id(&header, body, &key).unwrap();
        let id2 = StoredObject::derive_id(&header, body, &key).unwrap();

        assert_eq!(id1, id2);
    }

    #[test]
    fn stored_object_derive_id_differs_by_body() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let key = ObjectIdKey::from_bytes([0_u8; 32]);

        let id1 = StoredObject::derive_id(&header, b"body a", &key).unwrap();
        let id2 = StoredObject::derive_id(&header, b"body b", &key).unwrap();

        assert_ne!(id1, id2);
    }

    #[test]
    fn stored_object_serialization_roundtrip() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"body bytes".to_vec();

        let object_id = StoredObject::derive_id(&header, &body, &key).unwrap();

        let stored = StoredObject {
            object_id,
            header,
            body: body.clone(),
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        let json = serde_json::to_string(&stored).unwrap();
        let deserialized: StoredObject = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.body, body);
        assert_eq!(deserialized.object_id, object_id);
    }

    #[test]
    fn stored_object_canonical_bytes_rejects_oversized() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        // Create a body that exceeds MAX_CANONICAL_OBJECT_BYTES
        let oversized_body = vec![0_u8; fcp_cbor::MAX_CANONICAL_OBJECT_BYTES + 1];

        let result = StoredObject::canonical_bytes(&header, &oversized_body);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SerializationError::PayloadTooLarge { .. }
        ));
    }
}
