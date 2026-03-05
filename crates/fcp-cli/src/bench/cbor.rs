//! CBOR canonical serialization benchmarks.
//!
//! Microbenches for hot primitives in fcp-cbor:
//! - Schema hash computation
//! - Canonical CBOR serialization
//! - Canonical CBOR deserialization

use fcp_cbor::{CanonicalSerializer, SchemaId};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::runner::run_benchmark_with_result;
use super::types::{BenchmarkResult, Targets};

/// CBOR benchmark targets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CborTarget {
    SchemaHash,
    Serialize,
    Deserialize,
    All,
}

impl From<super::CborTarget> for CborTarget {
    fn from(t: super::CborTarget) -> Self {
        match t {
            super::CborTarget::SchemaHash => Self::SchemaHash,
            super::CborTarget::Serialize => Self::Serialize,
            super::CborTarget::Deserialize => Self::Deserialize,
            super::CborTarget::All => Self::All,
        }
    }
}

/// Run CBOR benchmarks based on the specified target.
pub fn run_benchmarks(
    target: super::CborTarget,
    iterations: u32,
    warmup: u32,
) -> Vec<BenchmarkResult> {
    let target: CborTarget = target.into();
    let mut results = Vec::new();

    if target == CborTarget::SchemaHash || target == CborTarget::All {
        results.push(bench_schema_hash(iterations, warmup));
    }

    if target == CborTarget::Serialize || target == CborTarget::All {
        results.push(bench_serialize_small(iterations, warmup));
        results.push(bench_serialize_medium(iterations, warmup));
    }

    if target == CborTarget::Deserialize || target == CborTarget::All {
        results.push(bench_deserialize_small(iterations, warmup));
        results.push(bench_deserialize_medium(iterations, warmup));
    }

    results
}

/// Small test struct for serialization benchmarks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SmallObject {
    id: u64,
    name: String,
    active: bool,
}

/// Medium test struct for serialization benchmarks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MediumObject {
    id: u64,
    name: String,
    description: String,
    tags: Vec<String>,
    metadata: std::collections::HashMap<String, String>,
    created_at: i64,
    updated_at: i64,
    version: u32,
    active: bool,
}

fn make_test_schema() -> SchemaId {
    SchemaId::new("fcp.bench", "TestObject", Version::new(1, 0, 0))
}

fn make_small_object() -> SmallObject {
    SmallObject {
        id: 12345,
        name: "benchmark-test".to_string(),
        active: true,
    }
}

fn make_medium_object() -> MediumObject {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());
    metadata.insert("key3".to_string(), "value3".to_string());

    MediumObject {
        id: 12345,
        name: "benchmark-test-medium".to_string(),
        description: "This is a medium-sized object for benchmarking canonical CBOR serialization performance. It includes multiple fields of varying types.".to_string(),
        tags: vec![
            "benchmark".to_string(),
            "cbor".to_string(),
            "serialization".to_string(),
            "performance".to_string(),
        ],
        metadata,
        created_at: 1_705_000_000,
        updated_at: 1_705_100_000,
        version: 42,
        active: true,
    }
}

fn bench_schema_hash(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || schema.hash());

    BenchmarkResult::new(
        "cbor-schema-hash",
        "Compute BLAKE3 schema hash from SchemaId",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "schema": format!("{}:{}@{}", schema.namespace, schema.name, schema.version),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.01, // 10 microseconds target.
        p99_target_ms: 0.1,  // 100 microseconds target.
    })
    .with_outliers(outliers)
}

fn bench_serialize_small(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_small_object();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-serialize-small",
        "Serialize small object to canonical CBOR with schema prefix",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "SmallObject",
        "fields": 3,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.05, // 50 microseconds target.
        p99_target_ms: 0.5,  // 500 microseconds target.
    })
    .with_outliers(outliers)
}

fn bench_serialize_medium(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_medium_object();

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-serialize-medium",
        "Serialize medium object to canonical CBOR with schema prefix",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "MediumObject",
        "fields": 9,
    }))
    .with_targets(Targets {
        p50_target_ms: 0.1, // 100 microseconds target.
        p99_target_ms: 1.0, // 1 millisecond target.
    })
    .with_outliers(outliers)
}

fn bench_deserialize_small(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_small_object();
    let bytes =
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::deserialize::<SmallObject>(&bytes, &schema)
            .expect("deserialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-deserialize-small",
        "Deserialize small object from canonical CBOR with schema verification",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "SmallObject",
        "fields": 3,
        "bytes": bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.1, // 100 microseconds target.
        p99_target_ms: 1.0, // 1 millisecond target.
    })
    .with_outliers(outliers)
}

fn bench_deserialize_medium(iterations: u32, warmup: u32) -> BenchmarkResult {
    let schema = make_test_schema();
    let obj = make_medium_object();
    let bytes =
        CanonicalSerializer::serialize(&obj, &schema).expect("serialization should not fail");

    let (percentiles, outliers) = run_benchmark_with_result(warmup, iterations, || {
        CanonicalSerializer::deserialize::<MediumObject>(&bytes, &schema)
            .expect("deserialization should not fail")
    });

    BenchmarkResult::new(
        "cbor-deserialize-medium",
        "Deserialize medium object from canonical CBOR with schema verification",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "object_type": "MediumObject",
        "fields": 9,
        "bytes": bytes.len(),
    }))
    .with_targets(Targets {
        p50_target_ms: 0.2, // 200 microseconds target.
        p99_target_ms: 2.0, // 2 milliseconds target.
    })
    .with_outliers(outliers)
}

trait BenchmarkResultExt {
    fn with_outliers(self, count: u32) -> Self;
}

impl BenchmarkResultExt for BenchmarkResult {
    fn with_outliers(mut self, count: u32) -> Self {
        self.outliers_detected = count;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CborTarget::from mapping ────────────────────────────────────────

    #[test]
    fn cbor_target_from_schema_hash() {
        let t: CborTarget = super::super::CborTarget::SchemaHash.into();
        assert_eq!(t, CborTarget::SchemaHash);
    }

    #[test]
    fn cbor_target_from_serialize() {
        let t: CborTarget = super::super::CborTarget::Serialize.into();
        assert_eq!(t, CborTarget::Serialize);
    }

    #[test]
    fn cbor_target_from_deserialize() {
        let t: CborTarget = super::super::CborTarget::Deserialize.into();
        assert_eq!(t, CborTarget::Deserialize);
    }

    #[test]
    fn cbor_target_from_all() {
        let t: CborTarget = super::super::CborTarget::All.into();
        assert_eq!(t, CborTarget::All);
    }

    // ── Test data generators ────────────────────────────────────────────

    #[test]
    fn make_test_schema_fields() {
        let schema = make_test_schema();
        assert_eq!(schema.namespace, "fcp.bench");
        assert_eq!(schema.name, "TestObject");
        assert_eq!(schema.version, Version::new(1, 0, 0));
    }

    #[test]
    fn make_small_object_fields() {
        let obj = make_small_object();
        assert_eq!(obj.id, 12345);
        assert_eq!(obj.name, "benchmark-test");
        assert!(obj.active);
    }

    #[test]
    fn make_medium_object_fields() {
        let obj = make_medium_object();
        assert_eq!(obj.id, 12345);
        assert_eq!(obj.tags.len(), 4);
        assert_eq!(obj.metadata.len(), 3);
        assert_eq!(obj.version, 42);
        assert!(obj.active);
    }

    // ── Schema hash determinism ─────────────────────────────────────────

    #[test]
    fn schema_hash_deterministic() {
        let s1 = make_test_schema();
        let s2 = make_test_schema();
        assert_eq!(s1.hash(), s2.hash());
    }

    // ── Serialization roundtrips ────────────────────────────────────────

    #[test]
    fn small_object_cbor_roundtrip() {
        let schema = make_test_schema();
        let obj = make_small_object();
        let bytes = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let back: SmallObject = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn medium_object_cbor_roundtrip() {
        let schema = make_test_schema();
        let obj = make_medium_object();
        let bytes = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let back: MediumObject = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn small_object_serialization_deterministic() {
        let schema = make_test_schema();
        let obj = make_small_object();
        let bytes1 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn medium_object_serialization_deterministic() {
        let schema = make_test_schema();
        let obj = make_medium_object();
        let bytes1 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&obj, &schema).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    // ── run_benchmarks dispatch ─────────────────────────────────────────

    #[test]
    fn run_benchmarks_schema_hash_returns_one() {
        let results = run_benchmarks(super::super::CborTarget::SchemaHash, 5, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "cbor-schema-hash");
    }

    #[test]
    fn run_benchmarks_serialize_returns_two() {
        let results = run_benchmarks(super::super::CborTarget::Serialize, 5, 1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "cbor-serialize-small");
        assert_eq!(results[1].name, "cbor-serialize-medium");
    }

    #[test]
    fn run_benchmarks_deserialize_returns_two() {
        let results = run_benchmarks(super::super::CborTarget::Deserialize, 5, 1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "cbor-deserialize-small");
        assert_eq!(results[1].name, "cbor-deserialize-medium");
    }

    #[test]
    fn run_benchmarks_all_returns_five() {
        let results = run_benchmarks(super::super::CborTarget::All, 5, 1);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn benchmark_results_have_percentiles() {
        let results = run_benchmarks(super::super::CborTarget::All, 5, 1);
        for r in &results {
            assert!(r.percentiles.is_some(), "missing percentiles for {}", r.name);
        }
    }

    #[test]
    fn benchmark_results_have_targets() {
        let results = run_benchmarks(super::super::CborTarget::All, 5, 1);
        for r in &results {
            assert!(r.targets.is_some(), "missing targets for {}", r.name);
            assert!(r.passed.is_some(), "missing passed for {}", r.name);
        }
    }

    // ── Small/medium serde (JSON) ──────────────────────────────────────

    #[test]
    fn small_object_json_roundtrip() {
        let obj = make_small_object();
        let json = serde_json::to_string(&obj).unwrap();
        let back: SmallObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn medium_object_json_roundtrip() {
        let obj = make_medium_object();
        let json = serde_json::to_string(&obj).unwrap();
        let back: MediumObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obj);
    }
}
