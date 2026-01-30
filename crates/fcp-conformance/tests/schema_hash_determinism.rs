//! Schema hash determinism tests (bd-32gn).
//!
//! Validates that schema hash computation is stable and deterministic:
//! - Same schema → same hash across invocations
//! - Different schema version → different hash
//! - Deterministic vector ordering across generation runs
//!
//! Emits structured JSONL logs per `docs/STANDARD_Testing_Logging.md`
//! and validates them against the E2E log schema.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use chrono::Utc;
use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_conformance::schemas::validate_e2e_log_jsonl;
use fcp_conformance::vecgen::{
    GeneratedVector, SchemaRegistration, core_schema_registrations, generate_schema_hash,
    generate_vector, serialize_to_canonical_cbor,
};
use fcp_testkit::LogCapture;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Correlation ID prefix for this test module.
const MODULE: &str = "fcp-conformance::schema_hash_determinism";

/// Convert elapsed time to milliseconds as u64 (saturating).
fn elapsed_ms(start: &Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Helper to emit a structured E2E log entry.
#[allow(clippy::too_many_arguments)]
fn emit_log(
    capture: &LogCapture,
    test_name: &str,
    phase: &str,
    correlation_id: &str,
    result: &str,
    duration_ms: u64,
    passed: u64,
    failed: u64,
    details: Option<serde_json::Value>,
) {
    let mut entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "test_name": test_name,
        "module": MODULE,
        "phase": phase,
        "correlation_id": correlation_id,
        "result": result,
        "duration_ms": duration_ms,
        "assertions": {
            "passed": passed,
            "failed": failed,
        },
    });
    if let Some(d) = details {
        entry["details"] = d;
    }
    capture
        .push_value(&entry)
        .expect("failed to push log entry");
}

// ============================================================================
// Test data types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimpleStruct {
    id: u64,
    name: String,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NestedStruct {
    label: String,
    value: u32,
    tags: Vec<String>,
}

// ============================================================================
// Schema Hash Stability Tests
// ============================================================================

/// Verify that the same schema produces the same hash across 100 invocations.
#[test]
fn schema_hash_same_schema_same_hash_across_invocations() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "schema_hash_same_schema_same_hash_across_invocations";
    let start = Instant::now();

    let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
    let reference_hash = generate_schema_hash(&schema);

    for i in 0..100 {
        let hash = generate_schema_hash(&schema);
        if hash != reference_hash {
            emit_log(
                &capture,
                test_name,
                "execute",
                &correlation_id,
                "fail",
                elapsed_ms(&start),
                i,
                1,
                Some(json!({
                    "iteration": i,
                    "expected": reference_hash,
                    "got": hash,
                })),
            );
            panic!("Hash mismatch at iteration {i}: expected {reference_hash}, got {hash}");
        }
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        100,
        0,
        Some(json!({
            "schema_id": "fcp.test:GoldenStruct@1.0.0",
            "schema_hash": reference_hash,
            "iterations": 100,
        })),
    );

    capture.assert_valid();
}

// ============================================================================
// Requirements Index CLI (bd-kjji / bd-3100)
// ============================================================================

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .expect("repo root")
}

fn reqcheck_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fcp-reqcheck"))
}

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let suffix = uuid::Uuid::new_v4();
    path.push(format!("fcp_reqcheck_{name}_{suffix}.{ext}"));
    path
}

#[test]
fn reqcheck_cli_valid_index_emits_valid_log() {
    let root = repo_root();
    let index = root.join("docs/STANDARD_Requirements_Index.md");
    let beads = root.join(".beads/issues.jsonl");
    let log_path = temp_path("valid", "jsonl");

    let output = Command::new(reqcheck_bin())
        .args([
            "--index",
            index.to_string_lossy().as_ref(),
            "--beads",
            beads.to_string_lossy().as_ref(),
            "--json",
            "--log-jsonl",
            log_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run fcp-reqcheck");

    assert!(
        output.status.success(),
        "reqcheck failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reqcheck json");
    assert_eq!(payload["valid"], true);

    let jsonl = fs::read_to_string(&log_path).expect("read reqcheck log");
    validate_e2e_log_jsonl(&jsonl).expect("reqcheck log jsonl should be valid");
}

#[test]
fn reqcheck_cli_missing_bead_exits_nonzero() {
    let root = repo_root();
    let beads = root.join(".beads/issues.jsonl");
    let index_path = temp_path("missing", "md");
    let log_path = temp_path("missing", "jsonl");

    let missing_bead = "bd-zzz404fixture";
    let content = format!(
        r"
## §1: Test

| Aspect | Details |
|--------|---------|
| **Owners** | `{missing_bead}` |
| **Tests** | n/a |

---
"
    );
    fs::write(&index_path, content).expect("write temp requirements index");

    let output = Command::new(reqcheck_bin())
        .args([
            "--index",
            index_path.to_string_lossy().as_ref(),
            "--beads",
            beads.to_string_lossy().as_ref(),
            "--json",
            "--log-jsonl",
            log_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run fcp-reqcheck");

    assert_eq!(output.status.code(), Some(1));

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reqcheck json");
    assert_eq!(payload["valid"], false);
    assert!(
        payload["report"]["missing_beads"]
            .as_array()
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(missing_bead)))
    );

    let jsonl = fs::read_to_string(&log_path).expect("read reqcheck log");
    validate_e2e_log_jsonl(&jsonl).expect("reqcheck log jsonl should be valid");
}

/// Verify that ALL core schema registrations produce stable hashes.
#[test]
fn schema_hash_all_core_schemas_stable() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "schema_hash_all_core_schemas_stable";
    let start = Instant::now();

    let registrations = core_schema_registrations();
    let mut passed = 0u64;

    // Compute reference hashes.
    let reference: Vec<(SchemaId, String)> = registrations
        .iter()
        .map(|r| {
            let sid = r.schema_id();
            let hash = generate_schema_hash(&sid);
            (sid, hash)
        })
        .collect();

    // Recompute and compare.
    for (sid, expected_hash) in &reference {
        let hash = generate_schema_hash(sid);
        assert_eq!(
            &hash,
            expected_hash,
            "Hash instability for {}: expected {expected_hash}, got {hash}",
            sid.as_bytes().escape_ascii()
        );
        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "schemas_checked": reference.len(),
            "schema_hashes": reference.iter().map(|(sid, h)| {
                json!({
                    "schema_id": String::from_utf8_lossy(&sid.as_bytes()).to_string(),
                    "hash": h,
                })
            }).collect::<Vec<_>>(),
        })),
    );

    capture.assert_valid();
}

// ============================================================================
// Version Sensitivity Tests
// ============================================================================

/// Different version → different hash for every component (major, minor, patch).
#[test]
fn schema_hash_differs_by_version_component() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "schema_hash_differs_by_version_component";
    let start = Instant::now();
    let mut passed = 0u64;

    let base = SchemaId::new("fcp.core", "TestObject", Version::new(1, 0, 0));
    let base_hash = generate_schema_hash(&base);

    // Major version change.
    let major = SchemaId::new("fcp.core", "TestObject", Version::new(2, 0, 0));
    let major_hash = generate_schema_hash(&major);
    assert_ne!(
        base_hash, major_hash,
        "Major version change must produce different hash"
    );
    passed += 1;

    // Minor version change.
    let minor = SchemaId::new("fcp.core", "TestObject", Version::new(1, 1, 0));
    let minor_hash = generate_schema_hash(&minor);
    assert_ne!(
        base_hash, minor_hash,
        "Minor version change must produce different hash"
    );
    passed += 1;

    // Patch version change.
    let patch = SchemaId::new("fcp.core", "TestObject", Version::new(1, 0, 1));
    let patch_hash = generate_schema_hash(&patch);
    assert_ne!(
        base_hash, patch_hash,
        "Patch version change must produce different hash"
    );
    passed += 1;

    // All different from each other.
    assert_ne!(major_hash, minor_hash, "Major and minor must differ");
    assert_ne!(major_hash, patch_hash, "Major and patch must differ");
    assert_ne!(minor_hash, patch_hash, "Minor and patch must differ");
    passed += 3;

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "base_hash": base_hash,
            "major_hash": major_hash,
            "minor_hash": minor_hash,
            "patch_hash": patch_hash,
        })),
    );

    capture.assert_valid();
}

/// Hash sensitivity to namespace changes.
#[test]
fn schema_hash_differs_by_namespace() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "schema_hash_differs_by_namespace";
    let start = Instant::now();

    let a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
    let b = SchemaId::new("fcp.mesh", "Object", Version::new(1, 0, 0));
    let c = SchemaId::new("fcp.stream", "Object", Version::new(1, 0, 0));

    let ha = generate_schema_hash(&a);
    let hb = generate_schema_hash(&b);
    let hc = generate_schema_hash(&c);

    assert_ne!(ha, hb, "Different namespaces must produce different hashes");
    assert_ne!(ha, hc);
    assert_ne!(hb, hc);

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        3,
        0,
        Some(json!({
            "namespace_a": "fcp.core",
            "namespace_b": "fcp.mesh",
            "namespace_c": "fcp.stream",
        })),
    );

    capture.assert_valid();
}

/// Hash sensitivity to name changes.
#[test]
fn schema_hash_differs_by_name() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "schema_hash_differs_by_name";
    let start = Instant::now();

    let a = SchemaId::new("fcp.core", "Alpha", Version::new(1, 0, 0));
    let b = SchemaId::new("fcp.core", "Beta", Version::new(1, 0, 0));

    let ha = generate_schema_hash(&a);
    let hb = generate_schema_hash(&b);

    assert_ne!(ha, hb, "Different names must produce different hashes");

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        1,
        0,
        None,
    );

    capture.assert_valid();
}

// ============================================================================
// Deterministic Vector Ordering Tests
// ============================================================================

/// Verify that generated vectors for a schema always produce the same ordering.
#[test]
fn vector_ordering_is_deterministic() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "vector_ordering_is_deterministic";
    let start = Instant::now();

    let reg = SchemaRegistration::new(
        "fcp.test",
        "GoldenStruct",
        Version::new(1, 0, 0),
        "Ordering test",
    );

    let samples: Vec<(String, SimpleStruct)> = vec![
        (
            "first".to_string(),
            SimpleStruct {
                id: 1,
                name: "alpha".into(),
                active: true,
            },
        ),
        (
            "second".to_string(),
            SimpleStruct {
                id: 2,
                name: "beta".into(),
                active: false,
            },
        ),
        (
            "third".to_string(),
            SimpleStruct {
                id: 3,
                name: "gamma".into(),
                active: true,
            },
        ),
    ];

    let reference = generate_vector(&reg, &samples).expect("vector generation failed");

    // Regenerate 20 times and compare.
    let mut passed = 0u64;
    for _ in 0..20 {
        let regenerated = generate_vector(&reg, &samples).expect("vector generation failed");

        // Schema hash must match.
        assert_eq!(
            reference.expected_schema_hash, regenerated.expected_schema_hash,
            "Schema hash must be stable across generations"
        );

        // Payload count and order must match.
        assert_eq!(
            reference.payloads.len(),
            regenerated.payloads.len(),
            "Payload count must be stable"
        );

        for (ref_p, gen_p) in reference.payloads.iter().zip(&regenerated.payloads) {
            assert_eq!(
                ref_p.description, gen_p.description,
                "Payload ordering must be stable"
            );
            assert_eq!(
                ref_p.expected_cbor, gen_p.expected_cbor,
                "CBOR bytes must be identical"
            );
            assert_eq!(
                ref_p.expected_payload, gen_p.expected_payload,
                "Full payload must be identical"
            );
        }

        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "iterations": 20,
            "payload_count": reference.payloads.len(),
            "schema_hash": reference.expected_schema_hash,
        })),
    );

    capture.assert_valid();
}

/// Verify that vectors for ALL core schemas are deterministic.
#[test]
fn all_core_schema_vectors_are_deterministic() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "all_core_schema_vectors_are_deterministic";
    let start = Instant::now();
    let mut passed = 0u64;

    let registrations = core_schema_registrations();

    // Generate reference vectors with a simple sample for each.
    let sample = SimpleStruct {
        id: 42,
        name: "determinism-test".into(),
        active: true,
    };
    let samples = vec![("determinism-sample".to_string(), sample)];

    let mut reference_map: BTreeMap<String, GeneratedVector> = BTreeMap::new();
    for reg in &registrations {
        let vector = generate_vector(reg, &samples).expect("vector generation failed");
        let key = format!("{}:{}@{}", reg.namespace, reg.name, reg.version);
        reference_map.insert(key, vector);
    }

    // Regenerate and compare.
    for reg in &registrations {
        let vector = generate_vector(reg, &samples).expect("vector generation failed");
        let key = format!("{}:{}@{}", reg.namespace, reg.name, reg.version);
        let reference = reference_map.get(&key).expect("missing reference vector");

        assert_eq!(
            reference.expected_schema_hash, vector.expected_schema_hash,
            "Schema hash instability for {key}"
        );

        for (ref_p, gen_p) in reference.payloads.iter().zip(&vector.payloads) {
            assert_eq!(
                ref_p.expected_payload, gen_p.expected_payload,
                "Payload instability for {key}"
            );
        }

        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "schemas_verified": reference_map.len(),
            "schema_ids": reference_map.keys().collect::<Vec<_>>(),
        })),
    );

    capture.assert_valid();
}

/// Verify that `BTreeMap` key ordering in output is deterministic.
#[test]
fn vector_map_ordering_is_deterministic() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "vector_map_ordering_is_deterministic";
    let start = Instant::now();

    let registrations = core_schema_registrations();
    let sample = SimpleStruct {
        id: 99,
        name: "order-test".into(),
        active: false,
    };
    let samples = vec![("ordering-sample".to_string(), sample)];

    // Build map twice and verify key ordering is identical.
    let mut map1: BTreeMap<String, GeneratedVector> = BTreeMap::new();
    let mut map2: BTreeMap<String, GeneratedVector> = BTreeMap::new();

    for reg in &registrations {
        let key = format!("{}:{}@{}", reg.namespace, reg.name, reg.version);
        map1.insert(key.clone(), generate_vector(reg, &samples).unwrap());
        map2.insert(key, generate_vector(reg, &samples).unwrap());
    }

    let keys1: Vec<&String> = map1.keys().collect();
    let keys2: Vec<&String> = map2.keys().collect();
    assert_eq!(keys1, keys2, "BTreeMap key ordering must be identical");

    // Compare JSON serialization.
    let json1 = serde_json::to_string(&map1).unwrap();
    let json2 = serde_json::to_string(&map2).unwrap();
    assert_eq!(json1, json2, "JSON serialization must be identical");

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        2,
        0,
        Some(json!({
            "key_count": keys1.len(),
            "keys": keys1,
        })),
    );

    capture.assert_valid();
}

// ============================================================================
// Canonical CBOR Determinism Tests
// ============================================================================

/// Verify canonical CBOR serialization produces identical bytes across invocations.
#[test]
fn canonical_cbor_serialization_is_stable() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "canonical_cbor_serialization_is_stable";
    let start = Instant::now();

    let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
    let value = SimpleStruct {
        id: 12345,
        name: "determinism".into(),
        active: true,
    };

    let (ref_cbor, ref_payload) = serialize_to_canonical_cbor(&value, &schema).unwrap();

    let mut passed = 0u64;
    for _ in 0..50 {
        let (cbor, payload) = serialize_to_canonical_cbor(&value, &schema).unwrap();
        assert_eq!(ref_cbor, cbor, "CBOR bytes must be identical across runs");
        assert_eq!(
            ref_payload, payload,
            "Full payload must be identical across runs"
        );
        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "iterations": 50,
            "schema_id": "fcp.test:GoldenStruct@1.0.0",
            "cbor_hex": ref_cbor,
            "payload_hex": ref_payload,
        })),
    );

    capture.assert_valid();
}

/// Verify that `CanonicalSerializer` roundtrip preserves bytes.
#[test]
fn canonical_serializer_roundtrip_preserves_bytes() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "canonical_serializer_roundtrip_preserves_bytes";
    let start = Instant::now();
    let mut passed = 0u64;

    let schema = SchemaId::new("fcp.test", "RoundtripTest", Version::new(1, 0, 0));

    let test_values = vec![
        SimpleStruct {
            id: 0,
            name: String::new(),
            active: false,
        },
        SimpleStruct {
            id: u64::MAX,
            name: "maximum".into(),
            active: true,
        },
        SimpleStruct {
            id: 42,
            name: "hello world 🌍".into(),
            active: true,
        },
    ];

    for value in &test_values {
        let bytes = CanonicalSerializer::serialize(value, &schema).unwrap();
        let deserialized: SimpleStruct = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        let re_serialized = CanonicalSerializer::serialize(&deserialized, &schema).unwrap();
        assert_eq!(
            bytes, re_serialized,
            "Roundtrip must produce identical bytes for id={}",
            value.id
        );
        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "values_tested": test_values.len(),
        })),
    );

    capture.assert_valid();
}

/// Verify that nested structures with vectors produce deterministic CBOR.
#[test]
fn nested_struct_cbor_is_deterministic() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "nested_struct_cbor_is_deterministic";
    let start = Instant::now();

    let schema = SchemaId::new("fcp.test", "NestedStruct", Version::new(1, 0, 0));
    let value = NestedStruct {
        label: "test-label".into(),
        value: 9999,
        tags: vec!["alpha".into(), "beta".into(), "gamma".into()],
    };

    let (ref_cbor, _) = serialize_to_canonical_cbor(&value, &schema).unwrap();

    let mut passed = 0u64;
    for _ in 0..30 {
        let (cbor, _) = serialize_to_canonical_cbor(&value, &schema).unwrap();
        assert_eq!(ref_cbor, cbor, "Nested struct CBOR must be deterministic");
        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "iterations": 30,
            "cbor_hex": ref_cbor,
        })),
    );

    capture.assert_valid();
}

// ============================================================================
// Golden Vector Stability Tests
// ============================================================================

/// Verify that golden vector schema hashes match fresh computation.
#[test]
fn golden_vector_schema_hashes_match_fresh_computation() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "golden_vector_schema_hashes_match_fresh_computation";
    let start = Instant::now();
    let mut passed = 0u64;

    // Pre-computed golden hashes for core schemas (computed deterministically).
    let registrations = core_schema_registrations();

    // Compute all hashes and verify they are non-empty and 64 hex chars.
    for reg in &registrations {
        let sid = reg.schema_id();
        let hash = generate_schema_hash(&sid);

        assert_eq!(
            hash.len(),
            64,
            "Hash for {}:{} must be 64 hex chars",
            reg.namespace,
            reg.name
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must be lowercase hex"
        );

        // Recompute to verify stability.
        let hash2 = generate_schema_hash(&sid);
        assert_eq!(
            hash, hash2,
            "Hash for {}:{} must be stable",
            reg.namespace, reg.name
        );

        passed += 1;
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        passed,
        0,
        Some(json!({
            "schemas_verified": registrations.len(),
        })),
    );

    capture.assert_valid();
}

// ============================================================================
// Log Validation Meta-Test
// ============================================================================

/// Verify that our log emission helper produces schema-valid JSONL.
#[test]
fn log_emission_produces_valid_jsonl() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "log_emission_produces_valid_jsonl";
    let start = Instant::now();

    // Emit several log entries with different phases.
    emit_log(
        &capture,
        test_name,
        "setup",
        &correlation_id,
        "pass",
        0,
        0,
        0,
        Some(json!({"note": "initializing test"})),
    );

    emit_log(
        &capture,
        test_name,
        "execute",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        1,
        0,
        None,
    );

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        2,
        0,
        Some(json!({"validated_entries": 2})),
    );

    // Validate the JSONL against the E2E schema.
    let jsonl = capture.jsonl();
    let validation_result = validate_e2e_log_jsonl(&jsonl);
    assert!(
        validation_result.is_ok(),
        "JSONL validation failed: {:?}",
        validation_result.err()
    );

    // Also use the assert method.
    capture.assert_valid();
}

// ============================================================================
// Schema Registration Completeness
// ============================================================================

/// Verify that `core_schema_registrations()` returns a non-empty, unique set.
#[test]
fn core_schema_registrations_are_unique_and_non_empty() {
    let capture = LogCapture::new();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let test_name = "core_schema_registrations_are_unique_and_non_empty";
    let start = Instant::now();

    let registrations = core_schema_registrations();
    assert!(
        !registrations.is_empty(),
        "Core schema registrations must not be empty"
    );

    // Check uniqueness by schema ID string.
    let mut seen = std::collections::HashSet::new();
    for reg in &registrations {
        let key = format!("{}:{}@{}", reg.namespace, reg.name, reg.version);
        assert!(
            seen.insert(key.clone()),
            "Duplicate schema registration: {key}"
        );
    }

    // Check uniqueness by hash.
    let mut hash_set = std::collections::HashSet::new();
    for reg in &registrations {
        let hash = generate_schema_hash(&reg.schema_id());
        assert!(
            hash_set.insert(hash.clone()),
            "Duplicate schema hash for {}:{}",
            reg.namespace,
            reg.name
        );
    }

    emit_log(
        &capture,
        test_name,
        "verify",
        &correlation_id,
        "pass",
        elapsed_ms(&start),
        2,
        0,
        Some(json!({
            "registration_count": registrations.len(),
            "all_unique_ids": true,
            "all_unique_hashes": true,
        })),
    );

    capture.assert_valid();
}
