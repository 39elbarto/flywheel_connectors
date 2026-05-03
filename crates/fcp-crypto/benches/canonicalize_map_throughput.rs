//! `canonicalize_map` throughput benchmark (br-m7aoz).
//!
//! Measures the per-map encode cost at sizes N ∈ {4, 16, 64, 256}
//! after the arena-based sort comparator landed. Pre-refactor the
//! function allocated a `Vec<u8>` per map entry just for the sort
//! key — N heap allocations per encode, recursively. Post-refactor
//! all keys live in a single arena Vec and the sort runs on
//! borrowed slices.
//!
//! Establishes the post-refactor baseline so a future regression
//! that re-introduces per-entry allocation gets caught
//! quantitatively.
//!
//! Run with `cargo bench -p fcp-crypto canonicalize_map_throughput`.

use std::hint::black_box;
use std::time::Duration;

use ciborium::value::{Integer, Value};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use fcp_crypto::canonicalize::to_deterministic_cbor;

/// Build a Value::Map with N text-keyed integer entries in
/// REVERSE-sorted input order, forcing the canonicalizer to
/// actually do work.
fn reverse_sorted_map(n: usize) -> Value {
    let mut entries = Vec::with_capacity(n);
    for i in (0..n).rev() {
        entries.push((
            Value::Text(format!("key-{i:04}")),
            Value::Integer(Integer::from(i as u64)),
        ));
    }
    Value::Map(entries)
}

/// Build a 2-level nested Map: outer N entries, each value is an
/// inner Map of M entries. Exercises the recursive canonicalize
/// path that fired the per-entry alloc on every level pre-refactor.
fn nested_reverse_sorted_map(outer: usize, inner: usize) -> Value {
    let mut entries = Vec::with_capacity(outer);
    for i in (0..outer).rev() {
        let mut inner_entries = Vec::with_capacity(inner);
        for j in (0..inner).rev() {
            inner_entries.push((
                Value::Text(format!("inner-{j:03}")),
                Value::Integer(Integer::from(j as u64)),
            ));
        }
        entries.push((
            Value::Text(format!("outer-{i:04}")),
            Value::Map(inner_entries),
        ));
    }
    Value::Map(entries)
}

fn bench_flat_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalize_map_flat");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_millis(500));

    for &n in &[4usize, 16, 64, 256] {
        let value = reverse_sorted_map(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                let bytes = to_deterministic_cbor(black_box(&value)).unwrap();
                black_box(bytes);
            });
        });
    }

    group.finish();
}

fn bench_nested_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalize_map_nested");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_millis(500));

    // Outer × inner pairs. Total entries = outer × (1 + inner).
    for &(outer, inner) in &[(4usize, 4usize), (16, 8), (32, 16), (64, 32)] {
        let value = nested_reverse_sorted_map(outer, inner);
        let total = outer * (1 + inner);
        group.throughput(Throughput::Elements(total as u64));
        group.bench_function(format!("outer={outer}_inner={inner}"), |b| {
            b.iter(|| {
                let bytes = to_deterministic_cbor(black_box(&value)).unwrap();
                black_box(bytes);
            });
        });
    }

    group.finish();
}

/// Pre-canonical input — the value's keys are already in canonical
/// order. Stresses the SORT-IS-CHEAP path. Post-refactor this
/// should be the same cost as the reverse case (sort_by short-
/// circuits on already-sorted input) modulo a few comparator calls.
fn bench_already_sorted_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalize_map_already_sorted");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_millis(500));

    for &n in &[4usize, 16, 64, 256] {
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            entries.push((
                Value::Text(format!("key-{i:04}")),
                Value::Integer(Integer::from(i as u64)),
            ));
        }
        let value = Value::Map(entries);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                let bytes = to_deterministic_cbor(black_box(&value)).unwrap();
                black_box(bytes);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_flat_map,
    bench_nested_map,
    bench_already_sorted_map,
);
criterion_main!(benches);
