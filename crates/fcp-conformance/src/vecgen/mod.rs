//! Schema hash and canonical CBOR vector generator.
//!
//! This module provides deterministic generation of golden vectors for:
//! - Schema hash verification (BLAKE3 with domain separator)
//! - Canonical CBOR encoding (RFC 8949 deterministic)
//! - `ObjectId` derivation (keyed BLAKE3)
//!
//! Generated vectors are normative: implementations MUST produce identical bytes.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fcp_cbor::{CanonicalSerializer, SCHEMA_HASH_LEN, SchemaId};
use semver::Version;
use serde::{Deserialize, Serialize};

/// Error type for vector generation.
#[derive(Debug, Clone)]
pub struct VecGenError {
    message: String,
}

impl VecGenError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for VecGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VecGenError {}

/// A registered schema with sample data generator.
#[derive(Debug, Clone)]
pub struct SchemaRegistration {
    /// Schema namespace (e.g., "fcp.core").
    pub namespace: String,
    /// Schema name (e.g., `CapabilityObject`).
    pub name: String,
    /// Schema version.
    pub version: Version,
    /// Description for documentation.
    pub description: String,
}

impl SchemaRegistration {
    /// Create a new schema registration.
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        version: Version,
        description: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            version,
            description: description.into(),
        }
    }

    /// Get the `SchemaId` for this registration.
    #[must_use]
    pub fn schema_id(&self) -> SchemaId {
        SchemaId::new(&self.namespace, &self.name, self.version.clone())
    }
}

/// Output format for generated vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedVector {
    /// Human-readable description.
    pub description: String,
    /// Schema namespace.
    pub schema_namespace: String,
    /// Schema name.
    pub schema_name: String,
    /// Schema version (major.minor.patch).
    pub schema_version: String,
    /// Expected schema hash (hex, 32 bytes).
    pub expected_schema_hash: String,
    /// Sample payloads with their canonical CBOR.
    pub payloads: Vec<PayloadVector>,
}

/// A single payload test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadVector {
    /// Description of this test case.
    pub description: String,
    /// Input data as JSON.
    pub input_json: serde_json::Value,
    /// Expected canonical CBOR bytes (hex).
    pub expected_cbor: String,
    /// Full canonical payload (`schema_hash` || cbor) as hex.
    pub expected_payload: String,
}

/// Generate schema hash for a given schema.
#[must_use]
pub fn generate_schema_hash(schema: &SchemaId) -> String {
    hex::encode(schema.hash().as_bytes())
}

/// Serialize a value to canonical CBOR and return hex.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_to_canonical_cbor<T: Serialize>(
    value: &T,
    schema: &SchemaId,
) -> Result<(String, String), VecGenError> {
    let payload = CanonicalSerializer::serialize(value, schema)
        .map_err(|e| VecGenError::new(format!("serialization failed: {e}")))?;

    let schema_hash_len = SCHEMA_HASH_LEN;
    if payload.len() < schema_hash_len {
        return Err(VecGenError::new("payload too short"));
    }

    let cbor_bytes = &payload[schema_hash_len..];
    let cbor_hex = hex::encode(cbor_bytes);
    let payload_hex = hex::encode(&payload);

    Ok((cbor_hex, payload_hex))
}

/// Generate a vector for a schema with sample data.
///
/// # Errors
///
/// Returns an error if vector generation fails.
pub fn generate_vector<T: Serialize>(
    registration: &SchemaRegistration,
    samples: &[(String, T)],
) -> Result<GeneratedVector, VecGenError> {
    let schema = registration.schema_id();
    let schema_hash = generate_schema_hash(&schema);

    let mut payloads = Vec::with_capacity(samples.len());
    for (desc, value) in samples {
        let input_json = serde_json::to_value(value)
            .map_err(|e| VecGenError::new(format!("JSON conversion failed: {e}")))?;
        let (cbor_hex, payload_hex) = serialize_to_canonical_cbor(value, &schema)?;

        payloads.push(PayloadVector {
            description: desc.clone(),
            input_json,
            expected_cbor: cbor_hex,
            expected_payload: payload_hex,
        });
    }

    Ok(GeneratedVector {
        description: registration.description.clone(),
        schema_namespace: registration.namespace.clone(),
        schema_name: registration.name.clone(),
        schema_version: registration.version.to_string(),
        expected_schema_hash: schema_hash,
        payloads,
    })
}

/// Write vectors to a JSON file.
///
/// # Errors
///
/// Returns an error if file writing fails.
pub fn write_vectors_to_file(
    vectors: &BTreeMap<String, GeneratedVector>,
    output_path: &Path,
) -> Result<(), VecGenError> {
    let json = serde_json::to_string_pretty(vectors)
        .map_err(|e| VecGenError::new(format!("JSON serialization failed: {e}")))?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VecGenError::new(format!("failed to create directory: {e}")))?;
    }

    fs::write(output_path, json)
        .map_err(|e| VecGenError::new(format!("failed to write file: {e}")))?;

    Ok(())
}

/// Core schema registrations for FCP2.
///
/// These are the normative schemas that require golden vectors.
#[must_use]
pub fn core_schema_registrations() -> Vec<SchemaRegistration> {
    vec![
        SchemaRegistration::new(
            "fcp.test",
            "GoldenStruct",
            Version::new(1, 0, 0),
            "Test struct for canonical CBOR verification",
        ),
        SchemaRegistration::new(
            "fcp.core",
            "CapabilityObject",
            Version::new(1, 0, 0),
            "Capability token wrapper object",
        ),
        SchemaRegistration::new(
            "fcp.core",
            "ObjectHeader",
            Version::new(1, 0, 0),
            "Universal object header with provenance",
        ),
        SchemaRegistration::new(
            "fcp.operation",
            "intent",
            Version::new(1, 0, 0),
            "Operation request with idempotency",
        ),
        SchemaRegistration::new(
            "fcp.operation",
            "receipt",
            Version::new(1, 0, 0),
            "Operation result receipt",
        ),
        SchemaRegistration::new(
            "fcp.core",
            "AuditEvent",
            Version::new(1, 0, 0),
            "Audit chain event entry",
        ),
        SchemaRegistration::new(
            "fcp.stream",
            "EventEnvelope",
            Version::new(1, 1, 0),
            "Streaming event wrapper",
        ),
        SchemaRegistration::new(
            "fcp.zone",
            "ZoneKeyManifest",
            Version::new(1, 0, 0),
            "Zone key distribution manifest",
        ),
        SchemaRegistration::new(
            "fcp.zone",
            "ZoneDefinition",
            Version::new(1, 0, 0),
            "Zone configuration and membership",
        ),
        SchemaRegistration::new(
            "fcp.mesh",
            "GossipSummary",
            Version::new(1, 0, 0),
            "Mesh gossip protocol summary",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestStruct {
        id: u64,
        name: String,
        active: bool,
    }

    #[test]
    fn schema_hash_is_deterministic() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let hash1 = generate_schema_hash(&schema);
        let hash2 = generate_schema_hash(&schema);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn canonical_cbor_is_deterministic() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let value = TestStruct {
            id: 42,
            name: "test".into(),
            active: true,
        };

        let (cbor1, _) = serialize_to_canonical_cbor(&value, &schema).unwrap();
        let (cbor2, _) = serialize_to_canonical_cbor(&value, &schema).unwrap();
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn schema_hash_differs_by_version() {
        let schema_v1 = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let schema_v2 = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 1));

        let hash1 = generate_schema_hash(&schema_v1);
        let hash2 = generate_schema_hash(&schema_v2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn generate_vector_works() {
        let reg = SchemaRegistration::new(
            "fcp.test",
            "GoldenStruct",
            Version::new(1, 0, 0),
            "Test struct",
        );

        let samples = vec![(
            "basic test".to_string(),
            TestStruct {
                id: 12345,
                name: "test".into(),
                active: true,
            },
        )];

        let vector = generate_vector(&reg, &samples).unwrap();
        assert_eq!(vector.schema_name, "GoldenStruct");
        assert_eq!(vector.payloads.len(), 1);
        assert!(!vector.expected_schema_hash.is_empty());
    }

    #[test]
    fn vector_order_is_deterministic() {
        let reg = SchemaRegistration::new(
            "fcp.test",
            "GoldenStruct",
            Version::new(1, 0, 0),
            "Test struct",
        );
        let samples = vec![(
            "basic test".to_string(),
            TestStruct {
                id: 12345,
                name: "test".into(),
                active: true,
            },
        )];
        let vector = generate_vector(&reg, &samples).unwrap();

        let mut map_a = BTreeMap::new();
        map_a.insert("b".to_string(), vector.clone());
        map_a.insert("a".to_string(), vector.clone());

        let mut map_b = BTreeMap::new();
        map_b.insert("a".to_string(), vector.clone());
        map_b.insert("b".to_string(), vector);

        let json_a = serde_json::to_string_pretty(&map_a).unwrap();
        let json_b = serde_json::to_string_pretty(&map_b).unwrap();
        assert_eq!(json_a, json_b);
    }

    // ── VecGenError tests ────────────────────────────────────

    #[test]
    fn vecgen_error_display() {
        let err = VecGenError::new("something went wrong");
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn vecgen_error_from_string() {
        let err = VecGenError::new(String::from("owned message"));
        assert_eq!(err.to_string(), "owned message");
    }

    #[test]
    fn vecgen_error_is_std_error() {
        let err = VecGenError::new("test");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn vecgen_error_debug_format() {
        let err = VecGenError::new("debug test");
        let debug = format!("{err:?}");
        assert!(debug.contains("debug test"));
    }

    #[test]
    fn vecgen_error_clone() {
        let err = VecGenError::new("clone test");
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    // ── SchemaRegistration tests ─────────────────────────────

    #[test]
    fn schema_registration_fields() {
        let reg = SchemaRegistration::new(
            "fcp.core",
            "CapabilityObject",
            Version::new(2, 1, 3),
            "A test registration",
        );
        assert_eq!(reg.namespace, "fcp.core");
        assert_eq!(reg.name, "CapabilityObject");
        assert_eq!(reg.version, Version::new(2, 1, 3));
        assert_eq!(reg.description, "A test registration");
    }

    #[test]
    fn schema_registration_schema_id_deterministic() {
        let reg = SchemaRegistration::new(
            "fcp.test",
            "Foo",
            Version::new(1, 0, 0),
            "desc",
        );
        let id1 = reg.schema_id();
        let id2 = reg.schema_id();
        assert_eq!(id1.hash().as_bytes(), id2.hash().as_bytes());
    }

    #[test]
    fn different_registrations_produce_different_schema_ids() {
        let reg_a = SchemaRegistration::new("fcp.a", "X", Version::new(1, 0, 0), "");
        let reg_b = SchemaRegistration::new("fcp.b", "X", Version::new(1, 0, 0), "");
        assert_ne!(
            generate_schema_hash(&reg_a.schema_id()),
            generate_schema_hash(&reg_b.schema_id()),
        );
    }

    #[test]
    fn schema_hash_differs_by_name() {
        let reg_a = SchemaRegistration::new("fcp.test", "Alpha", Version::new(1, 0, 0), "");
        let reg_b = SchemaRegistration::new("fcp.test", "Beta", Version::new(1, 0, 0), "");
        assert_ne!(
            generate_schema_hash(&reg_a.schema_id()),
            generate_schema_hash(&reg_b.schema_id()),
        );
    }

    // ── core_schema_registrations tests ──────────────────────

    #[test]
    fn core_registrations_not_empty() {
        let regs = core_schema_registrations();
        assert!(!regs.is_empty());
    }

    #[test]
    fn core_registrations_have_unique_schema_ids() {
        let regs = core_schema_registrations();
        let hashes: Vec<String> = regs.iter().map(|r| generate_schema_hash(&r.schema_id())).collect();
        let unique: std::collections::HashSet<&String> = hashes.iter().collect();
        assert_eq!(hashes.len(), unique.len(), "all core registrations must have unique hashes");
    }

    #[test]
    fn core_registrations_have_descriptions() {
        for reg in core_schema_registrations() {
            assert!(!reg.description.is_empty(), "registration {} should have description", reg.name);
        }
    }

    #[test]
    fn core_registrations_have_namespaces() {
        for reg in core_schema_registrations() {
            assert!(reg.namespace.starts_with("fcp."), "registration {} namespace should start with fcp.", reg.name);
        }
    }

    #[test]
    fn core_registrations_count() {
        let regs = core_schema_registrations();
        assert!(regs.len() >= 10, "should have at least 10 core registrations, got {}", regs.len());
    }

    // ── serialize_to_canonical_cbor tests ────────────────────

    #[test]
    fn canonical_cbor_payload_starts_with_schema_hash() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let value = TestStruct { id: 1, name: "x".into(), active: false };
        let (cbor_hex, payload_hex) = serialize_to_canonical_cbor(&value, &schema).unwrap();
        let expected_hash = generate_schema_hash(&schema);
        assert!(payload_hex.starts_with(&expected_hash), "payload should start with schema hash");
        assert!(payload_hex.ends_with(&cbor_hex), "payload should end with cbor");
    }

    #[test]
    fn canonical_cbor_different_values_different_bytes() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let v1 = TestStruct { id: 1, name: "a".into(), active: true };
        let v2 = TestStruct { id: 2, name: "b".into(), active: false };
        let (cbor1, _) = serialize_to_canonical_cbor(&v1, &schema).unwrap();
        let (cbor2, _) = serialize_to_canonical_cbor(&v2, &schema).unwrap();
        assert_ne!(cbor1, cbor2);
    }

    #[test]
    fn canonical_cbor_same_schema_same_hash_prefix() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let v1 = TestStruct { id: 1, name: "a".into(), active: true };
        let v2 = TestStruct { id: 99, name: "z".into(), active: false };
        let (_, payload1) = serialize_to_canonical_cbor(&v1, &schema).unwrap();
        let (_, payload2) = serialize_to_canonical_cbor(&v2, &schema).unwrap();
        // First 64 hex chars (32 bytes) should be same schema hash
        assert_eq!(&payload1[..64], &payload2[..64]);
    }

    // ── generate_vector tests ────────────────────────────────

    #[test]
    fn generate_vector_multiple_samples() {
        let reg = SchemaRegistration::new("fcp.test", "Multi", Version::new(1, 0, 0), "multi");
        let samples = vec![
            ("first".to_string(), TestStruct { id: 1, name: "a".into(), active: true }),
            ("second".to_string(), TestStruct { id: 2, name: "b".into(), active: false }),
            ("third".to_string(), TestStruct { id: 3, name: "c".into(), active: true }),
        ];
        let vector = generate_vector(&reg, &samples).unwrap();
        assert_eq!(vector.payloads.len(), 3);
        assert_eq!(vector.payloads[0].description, "first");
        assert_eq!(vector.payloads[1].description, "second");
        assert_eq!(vector.payloads[2].description, "third");
    }

    #[test]
    fn generate_vector_preserves_schema_info() {
        let reg = SchemaRegistration::new("fcp.zone", "ZoneKey", Version::new(3, 2, 1), "zone key");
        let samples = vec![("s".to_string(), TestStruct { id: 0, name: String::new(), active: false })];
        let vector = generate_vector(&reg, &samples).unwrap();
        assert_eq!(vector.schema_namespace, "fcp.zone");
        assert_eq!(vector.schema_name, "ZoneKey");
        assert_eq!(vector.schema_version, "3.2.1");
        assert_eq!(vector.description, "zone key");
    }

    #[test]
    fn generate_vector_empty_samples() {
        let reg = SchemaRegistration::new("fcp.test", "Empty", Version::new(1, 0, 0), "empty");
        let samples: Vec<(String, TestStruct)> = vec![];
        let vector = generate_vector(&reg, &samples).unwrap();
        assert!(vector.payloads.is_empty());
        assert!(!vector.expected_schema_hash.is_empty());
    }

    #[test]
    fn generate_vector_payload_json_roundtrip() {
        let reg = SchemaRegistration::new("fcp.test", "RT", Version::new(1, 0, 0), "roundtrip");
        let input = TestStruct { id: 42, name: "hello".into(), active: true };
        let samples = vec![("rt".to_string(), input)];
        let vector = generate_vector(&reg, &samples).unwrap();
        let json = &vector.payloads[0].input_json;
        assert_eq!(json["id"], 42);
        assert_eq!(json["name"], "hello");
        assert_eq!(json["active"], true);
    }

    // ── write_vectors_to_file tests ──────────────────────────

    #[test]
    fn write_vectors_to_file_creates_file() {
        let dir = std::env::temp_dir().join(format!("fcp_vecgen_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_vectors.json");

        let reg = SchemaRegistration::new("fcp.test", "WF", Version::new(1, 0, 0), "write test");
        let samples = vec![("s".to_string(), TestStruct { id: 1, name: "w".into(), active: true })];
        let vector = generate_vector(&reg, &samples).unwrap();

        let mut map = BTreeMap::new();
        map.insert("test".to_string(), vector);

        write_vectors_to_file(&map, &path).unwrap();
        assert!(path.exists());

        let content = fs::read_to_string(&path).unwrap();
        let parsed: BTreeMap<String, GeneratedVector> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains_key("test"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_vectors_to_file_creates_parent_dirs() {
        let dir = std::env::temp_dir().join(format!("fcp_vecgen_nested_{}", std::process::id()));
        let path = dir.join("nested").join("deep").join("vectors.json");

        let map = BTreeMap::new();
        write_vectors_to_file(&map, &path).unwrap();
        assert!(path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_vectors_to_file_invalid_path() {
        let path = Path::new("/dev/null/impossible/path.json");
        let map = BTreeMap::new();
        let result = write_vectors_to_file(&map, path);
        assert!(result.is_err());
    }

    // ── GeneratedVector / PayloadVector serde tests ──────────

    #[test]
    fn generated_vector_json_roundtrip() {
        let reg = SchemaRegistration::new("fcp.test", "Serde", Version::new(1, 0, 0), "serde");
        let samples = vec![("s".to_string(), TestStruct { id: 7, name: "json".into(), active: false })];
        let vector = generate_vector(&reg, &samples).unwrap();

        let json = serde_json::to_string(&vector).unwrap();
        let parsed: GeneratedVector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_name, "Serde");
        assert_eq!(parsed.payloads.len(), 1);
        assert_eq!(parsed.expected_schema_hash, vector.expected_schema_hash);
    }

    #[test]
    fn payload_vector_json_roundtrip() {
        let pv = PayloadVector {
            description: "test payload".into(),
            input_json: serde_json::json!({"x": 1}),
            expected_cbor: "aabb".into(),
            expected_payload: "ccdd".into(),
        };
        let json = serde_json::to_string(&pv).unwrap();
        let parsed: PayloadVector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.description, "test payload");
        assert_eq!(parsed.expected_cbor, "aabb");
    }

    // ── schema hash format tests ─────────────────────────────

    #[test]
    fn schema_hash_is_64_hex_chars() {
        for reg in core_schema_registrations() {
            let hash = generate_schema_hash(&reg.schema_id());
            assert_eq!(hash.len(), 64, "hash for {} should be 64 hex chars", reg.name);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "hash should be hex");
        }
    }

    #[test]
    fn schema_hash_lowercase() {
        let schema = SchemaId::new("fcp.test", "Case", Version::new(1, 0, 0));
        let hash = generate_schema_hash(&schema);
        assert_eq!(hash, hash.to_lowercase(), "hash should be lowercase hex");
    }

    // ── core_schema_registrations CBOR serialization tests ───

    #[test]
    fn core_registrations_each_produces_distinct_hash() {
        let regs = core_schema_registrations();
        let hashes: Vec<String> = regs.iter().map(|r| generate_schema_hash(&r.schema_id())).collect();
        for (i, h1) in hashes.iter().enumerate() {
            for (j, h2) in hashes.iter().enumerate() {
                if i != j {
                    assert_ne!(h1, h2, "registrations {} and {} should have distinct hashes", regs[i].name, regs[j].name);
                }
            }
        }
    }

    #[test]
    fn core_registrations_schema_ids_are_stable() {
        let regs1 = core_schema_registrations();
        let regs2 = core_schema_registrations();
        for (r1, r2) in regs1.iter().zip(regs2.iter()) {
            assert_eq!(
                generate_schema_hash(&r1.schema_id()),
                generate_schema_hash(&r2.schema_id()),
                "schema hash for {} must be stable across calls",
                r1.name
            );
        }
    }

    #[test]
    fn core_registrations_versions_are_valid() {
        for reg in core_schema_registrations() {
            assert!(reg.version.major >= 1 || reg.version.minor >= 1, "version for {} should be non-zero", reg.name);
        }
    }

    #[test]
    fn core_registrations_names_not_empty() {
        for reg in core_schema_registrations() {
            assert!(!reg.name.is_empty(), "name must not be empty");
        }
    }

    // ── SchemaRegistration derive tests ─────────────────────

    #[test]
    fn schema_registration_debug() {
        let reg = SchemaRegistration::new("fcp.test", "Dbg", Version::new(1, 0, 0), "debug test");
        let debug = format!("{reg:?}");
        assert!(debug.contains("Dbg"));
        assert!(debug.contains("fcp.test"));
    }

    #[test]
    fn schema_registration_clone() {
        let reg = SchemaRegistration::new("fcp.test", "Cln", Version::new(2, 3, 4), "clone test");
        let cloned = reg.clone();
        assert_eq!(reg.namespace, cloned.namespace);
        assert_eq!(reg.name, cloned.name);
        assert_eq!(reg.version, cloned.version);
        assert_eq!(reg.description, cloned.description);
    }

    // ── GeneratedVector / PayloadVector derive tests ────────

    #[test]
    fn generated_vector_clone() {
        let reg = SchemaRegistration::new("fcp.test", "Cln", Version::new(1, 0, 0), "");
        let samples = vec![("s".to_string(), TestStruct { id: 1, name: "c".into(), active: true })];
        let vector = generate_vector(&reg, &samples).unwrap();
        let cloned = vector.clone();
        assert_eq!(vector.schema_name, cloned.schema_name);
        assert_eq!(vector.payloads.len(), cloned.payloads.len());
        assert_eq!(vector.expected_schema_hash, cloned.expected_schema_hash);
    }

    #[test]
    fn generated_vector_debug() {
        let reg = SchemaRegistration::new("fcp.test", "Dbg", Version::new(1, 0, 0), "");
        let samples: Vec<(String, TestStruct)> = vec![];
        let vector = generate_vector(&reg, &samples).unwrap();
        let debug = format!("{vector:?}");
        assert!(debug.contains("Dbg"));
    }

    #[test]
    fn payload_vector_clone() {
        let pv = PayloadVector {
            description: "test".into(),
            input_json: serde_json::json!({"a": 1}),
            expected_cbor: "ab".into(),
            expected_payload: "cd".into(),
        };
        let cloned = pv.clone();
        assert_eq!(pv.description, cloned.description);
        assert_eq!(pv.expected_cbor, cloned.expected_cbor);
    }

    #[test]
    fn payload_vector_debug() {
        let pv = PayloadVector {
            description: "dbg".into(),
            input_json: serde_json::json!(null),
            expected_cbor: String::new(),
            expected_payload: String::new(),
        };
        let debug = format!("{pv:?}");
        assert!(debug.contains("dbg"));
    }

    // ── write_vectors_to_file overwrite test ────────────────

    #[test]
    fn write_vectors_to_file_overwrites_existing() {
        let dir = std::env::temp_dir().join(format!("fcp_vecgen_overwrite_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("overwrite.json");

        let mut map1 = BTreeMap::new();
        let reg = SchemaRegistration::new("fcp.test", "V1", Version::new(1, 0, 0), "first");
        let v1 = generate_vector(&reg, &[(String::new(), TestStruct { id: 1, name: String::new(), active: false })]).unwrap();
        map1.insert("key".to_string(), v1);
        write_vectors_to_file(&map1, &path).unwrap();

        let mut map2 = BTreeMap::new();
        let reg2 = SchemaRegistration::new("fcp.test", "V2", Version::new(2, 0, 0), "second");
        let v2 = generate_vector(&reg2, &[(String::new(), TestStruct { id: 2, name: String::new(), active: true })]).unwrap();
        map2.insert("key".to_string(), v2);
        write_vectors_to_file(&map2, &path).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let parsed: BTreeMap<String, GeneratedVector> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["key"].schema_name, "V2", "second write should overwrite first");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── schema hash edge cases ──────────────────────────────

    #[test]
    fn schema_hash_empty_namespace() {
        let s1 = SchemaId::new("", "X", Version::new(1, 0, 0));
        let s2 = SchemaId::new("fcp.test", "X", Version::new(1, 0, 0));
        assert_ne!(generate_schema_hash(&s1), generate_schema_hash(&s2));
    }

    #[test]
    fn schema_hash_empty_name() {
        let s1 = SchemaId::new("fcp.test", "", Version::new(1, 0, 0));
        let s2 = SchemaId::new("fcp.test", "X", Version::new(1, 0, 0));
        assert_ne!(generate_schema_hash(&s1), generate_schema_hash(&s2));
    }

    #[test]
    fn schema_hash_major_minor_patch_all_differ() {
        let v1 = SchemaId::new("fcp.test", "T", Version::new(1, 0, 0));
        let v2 = SchemaId::new("fcp.test", "T", Version::new(0, 1, 0));
        let v3 = SchemaId::new("fcp.test", "T", Version::new(0, 0, 1));
        let h1 = generate_schema_hash(&v1);
        let h2 = generate_schema_hash(&v2);
        let h3 = generate_schema_hash(&v3);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    // ── canonical CBOR edge cases ───────────────────────────

    #[test]
    fn canonical_cbor_empty_string_field() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let v = TestStruct { id: 0, name: String::new(), active: false };
        let result = serialize_to_canonical_cbor(&v, &schema);
        assert!(result.is_ok());
        let (cbor, payload) = result.unwrap();
        assert!(!cbor.is_empty());
        assert!(!payload.is_empty());
    }

    #[test]
    fn canonical_cbor_large_id() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let v = TestStruct { id: u64::MAX, name: "max".into(), active: true };
        let result = serialize_to_canonical_cbor(&v, &schema);
        assert!(result.is_ok());
    }

    #[test]
    fn canonical_cbor_unicode_name() {
        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let v = TestStruct { id: 1, name: "日本語テスト🎉".into(), active: true };
        let (cbor1, _) = serialize_to_canonical_cbor(&v, &schema).unwrap();
        let (cbor2, _) = serialize_to_canonical_cbor(&v, &schema).unwrap();
        assert_eq!(cbor1, cbor2, "unicode CBOR must be deterministic");
    }

    // ── generate_vector edge cases ──────────────────────────

    #[test]
    fn generate_vector_single_sample_has_correct_hash() {
        let reg = SchemaRegistration::new("fcp.test", "HashCheck", Version::new(1, 0, 0), "hash");
        let schema = reg.schema_id();
        let expected_hash = generate_schema_hash(&schema);
        let samples = vec![("s".to_string(), TestStruct { id: 1, name: "h".into(), active: true })];
        let vector = generate_vector(&reg, &samples).unwrap();
        assert_eq!(vector.expected_schema_hash, expected_hash);
    }

    #[test]
    fn generate_vector_payload_cbor_starts_after_hash() {
        let reg = SchemaRegistration::new("fcp.test", "Split", Version::new(1, 0, 0), "split");
        let samples = vec![("s".to_string(), TestStruct { id: 5, name: "x".into(), active: false })];
        let vector = generate_vector(&reg, &samples).unwrap();
        let payload = &vector.payloads[0];
        assert!(payload.expected_payload.starts_with(&vector.expected_schema_hash));
        assert!(payload.expected_payload.ends_with(&payload.expected_cbor));
        assert_eq!(
            payload.expected_payload.len(),
            vector.expected_schema_hash.len() + payload.expected_cbor.len()
        );
    }
}
