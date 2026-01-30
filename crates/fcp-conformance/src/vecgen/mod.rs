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
}
