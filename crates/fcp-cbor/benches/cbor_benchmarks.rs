//! Benchmarks for fcp-cbor hot paths.
//!
//! These benchmarks verify performance of the critical CBOR operations:
//! - Schema hash computation (type binding for all objects)
//! - Canonical serialization (content addressing)
//! - Deserialization with schema verification

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use fcp_cbor::{CanonicalSerializer, SchemaId, to_canonical_cbor};
use semver::Version;
use serde::{Deserialize, Serialize};

// ============================================================================
// Test Types
// ============================================================================

/// Small payload (~50 bytes serialized)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SmallPayload {
    id: u64,
    name: String,
    active: bool,
}

/// Medium payload (~500 bytes serialized)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MediumPayload {
    id: u64,
    name: String,
    description: String,
    tags: Vec<String>,
    metadata: Vec<(String, String)>,
}

/// Large payload (~5KB serialized)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LargePayload {
    id: u64,
    entries: Vec<MediumPayload>,
}

fn make_small_payload() -> SmallPayload {
    SmallPayload {
        id: 12345,
        name: "test-object".to_string(),
        active: true,
    }
}

fn make_medium_payload() -> MediumPayload {
    MediumPayload {
        id: 67890,
        name: "medium-test-object".to_string(),
        description: "A medium-sized test object with multiple fields for benchmarking \
                      canonical CBOR serialization performance across typical payload sizes."
            .to_string(),
        tags: vec![
            "benchmark".to_string(),
            "cbor".to_string(),
            "canonical".to_string(),
            "fcp2".to_string(),
            "serialization".to_string(),
        ],
        metadata: vec![
            ("version".to_string(), "1.0.0".to_string()),
            ("author".to_string(), "benchmark".to_string()),
            ("created".to_string(), "2025-01-01T00:00:00Z".to_string()),
            ("priority".to_string(), "high".to_string()),
        ],
    }
}

fn make_large_payload() -> LargePayload {
    LargePayload {
        id: 11111,
        entries: (0..10)
            .map(|i| {
                let mut m = make_medium_payload();
                m.id = i;
                m.name = format!("entry-{i}");
                m
            })
            .collect(),
    }
}

// ============================================================================
// Schema Hash Benchmarks
// ============================================================================

fn bench_schema_hash(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(2, 0, 0));

    c.bench_function("schema_hash", |b| {
        b.iter(|| {
            let _ = black_box(&schema).hash();
        });
    });
}

fn bench_schema_hash_long_name(c: &mut Criterion) {
    let schema = SchemaId::new(
        "fcp.connector.external.messaging",
        "LongNamedTypeWithManyCharacters",
        Version::new(1, 2, 3),
    );

    c.bench_function("schema_hash_long_name", |b| {
        b.iter(|| {
            let _ = black_box(&schema).hash();
        });
    });
}

// ============================================================================
// Serialization Benchmarks
// ============================================================================

fn bench_serialize_small(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.test", "SmallPayload", Version::new(1, 0, 0));
    let payload = make_small_payload();

    c.bench_function("serialize_small", |b| {
        b.iter(|| {
            let _ = CanonicalSerializer::serialize(black_box(&payload), black_box(&schema));
        });
    });
}

fn bench_serialize_medium(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.test", "MediumPayload", Version::new(1, 0, 0));
    let payload = make_medium_payload();

    // Compute actual serialized size for accurate throughput measurement
    let serialized_size = CanonicalSerializer::serialize(&payload, &schema)
        .expect("serialization should succeed")
        .len() as u64;

    let mut group = c.benchmark_group("serialize");
    group.throughput(Throughput::Bytes(serialized_size));
    group.bench_function("serialize_medium", |b| {
        b.iter(|| {
            let _ = CanonicalSerializer::serialize(black_box(&payload), black_box(&schema));
        });
    });
    group.finish();
}

fn bench_serialize_large(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.test", "LargePayload", Version::new(1, 0, 0));
    let payload = make_large_payload();

    // Compute actual serialized size for accurate throughput measurement
    let serialized_size = CanonicalSerializer::serialize(&payload, &schema)
        .expect("serialization should succeed")
        .len() as u64;

    let mut group = c.benchmark_group("serialize_large");
    group.throughput(Throughput::Bytes(serialized_size));
    group.bench_function("serialize_large", |b| {
        b.iter(|| {
            let _ = CanonicalSerializer::serialize(black_box(&payload), black_box(&schema));
        });
    });
    group.finish();
}

// ============================================================================
// Deserialization Benchmarks
// ============================================================================

fn bench_deserialize_small(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.test", "SmallPayload", Version::new(1, 0, 0));
    let payload = make_small_payload();
    let bytes = CanonicalSerializer::serialize(&payload, &schema).unwrap();

    c.bench_function("deserialize_small", |b| {
        b.iter(|| {
            let _: SmallPayload =
                CanonicalSerializer::deserialize(black_box(&bytes), black_box(&schema)).unwrap();
        });
    });
}

fn bench_deserialize_medium(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.test", "MediumPayload", Version::new(1, 0, 0));
    let payload = make_medium_payload();
    let bytes = CanonicalSerializer::serialize(&payload, &schema).unwrap();

    let mut group = c.benchmark_group("deserialize");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("deserialize_medium", |b| {
        b.iter(|| {
            let _: MediumPayload =
                CanonicalSerializer::deserialize(black_box(&bytes), black_box(&schema)).unwrap();
        });
    });
    group.finish();
}

fn bench_deserialize_unchecked_medium(c: &mut Criterion) {
    let schema = SchemaId::new("fcp.test", "MediumPayload", Version::new(1, 0, 0));
    let payload = make_medium_payload();
    let bytes = CanonicalSerializer::serialize(&payload, &schema).unwrap();

    let mut group = c.benchmark_group("deserialize_unchecked");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("deserialize_unchecked_medium", |b| {
        b.iter(|| {
            let _: MediumPayload =
                CanonicalSerializer::deserialize_unchecked(black_box(&bytes), black_box(&schema))
                    .unwrap();
        });
    });
    group.finish();
}

// ============================================================================
// Raw Canonical CBOR Benchmarks
// ============================================================================

fn bench_to_canonical_cbor_small(c: &mut Criterion) {
    let payload = make_small_payload();

    c.bench_function("to_canonical_cbor_small", |b| {
        b.iter(|| {
            let _ = to_canonical_cbor(black_box(&payload));
        });
    });
}

fn bench_to_canonical_cbor_medium(c: &mut Criterion) {
    let payload = make_medium_payload();

    c.bench_function("to_canonical_cbor_medium", |b| {
        b.iter(|| {
            let _ = to_canonical_cbor(black_box(&payload));
        });
    });
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    schema_benches,
    bench_schema_hash,
    bench_schema_hash_long_name,
);

criterion_group!(
    serialize_benches,
    bench_serialize_small,
    bench_serialize_medium,
    bench_serialize_large,
);

criterion_group!(
    deserialize_benches,
    bench_deserialize_small,
    bench_deserialize_medium,
    bench_deserialize_unchecked_medium,
);

criterion_group!(
    raw_cbor_benches,
    bench_to_canonical_cbor_small,
    bench_to_canonical_cbor_medium,
);

criterion_main!(
    schema_benches,
    serialize_benches,
    deserialize_benches,
    raw_cbor_benches
);
