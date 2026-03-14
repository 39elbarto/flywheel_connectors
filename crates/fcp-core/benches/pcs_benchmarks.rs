//! PCS Zones (MLS/TreeKEM) benchmarks for personal mesh feasibility.
//!
//! Measures key update latency and memory footprint for group sizes n=3..10,
//! as required by the PCS Zones acceptance criteria (6o25.5.1).

use criterion::{Criterion, criterion_group, criterion_main};
use fcp_core::pcs::{GroupMember, PcsGroupState};
use fcp_core::ZoneId;
use fcp_crypto::x25519::X25519SecretKey;
use rand::RngCore;

fn random_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn make_members(n: usize) -> Vec<GroupMember> {
    (0..n)
        .map(|i| {
            let sk = X25519SecretKey::generate();
            GroupMember {
                node_id: fcp_core::TailscaleNodeId::new(format!("node-{i}")),
                public_key: sk.public_key(),
                leaf_index: u32::try_from(i).unwrap_or(0),
            }
        })
        .collect()
}

fn make_group(n: usize) -> PcsGroupState {
    let members = make_members(n);
    PcsGroupState::new(ZoneId::owner(), members, random_secret()).unwrap()
}

fn bench_group_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_group_creation");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter(|| {
                let members = make_members(n);
                let _ = std::hint::black_box(
                    PcsGroupState::new(ZoneId::owner(), members, random_secret()).unwrap(),
                );
            });
        });
    }
    group.finish();
}

fn bench_epoch_advance(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_epoch_advance");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}"), |b| {
            let mut state = make_group(n);
            b.iter(|| {
                let _ = std::hint::black_box(state.advance_epoch().unwrap());
            });
        });
    }
    group.finish();
}

fn bench_zone_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_zone_key_derivation");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}"), |b| {
            let state = make_group(n);
            b.iter(|| {
                let _ = std::hint::black_box(state.derive_zone_key().unwrap());
            });
        });
    }
    group.finish();
}

fn bench_member_removal_rekey(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_member_removal_rekey");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter_batched(
                || make_group(n),
                |mut state| {
                    let node_id = state.members()[1].node_id.clone();
                    let _ = std::hint::black_box(state.remove_member(&node_id).unwrap());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_member_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_member_add");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter_batched(
                || make_group(n),
                |mut state| {
                    let sk = X25519SecretKey::generate();
                    let new_member = GroupMember {
                        node_id: fcp_core::TailscaleNodeId::new("new-node"),
                        public_key: sk.public_key(),
                        leaf_index: u32::try_from(n).unwrap_or(0),
                    };
                    let _ = std::hint::black_box(state.add_member(new_member).unwrap());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_memory_footprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_memory_footprint");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}_size_of"), |b| {
            let state = make_group(n);
            b.iter(|| {
                // Measure approximate memory: struct size + member vec + epoch secret
                let base = std::mem::size_of::<PcsGroupState>();
                let members = state.member_count() * std::mem::size_of::<GroupMember>();
                std::hint::black_box(base + members)
            });
        });
    }
    group.finish();
}

fn bench_compromise_recovery_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_compromise_recovery");
    for n in [3, 4, 5, 6, 8, 10] {
        group.bench_function(format!("n={n}"), |b| {
            b.iter_batched(
                || {
                    let mut state = make_group(n);
                    // Advance a few epochs to simulate normal operation
                    for _ in 0..3 {
                        state.advance_epoch().unwrap();
                    }
                    state
                },
                |mut state| {
                    // Full compromise recovery: remove + rekey
                    let compromised = state.members()[1].node_id.clone();
                    let _ = std::hint::black_box(state.remove_member(&compromised).unwrap());
                    // Advance epoch to fully invalidate compromised keys
                    let _ = std::hint::black_box(state.advance_epoch().unwrap());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_group_creation,
    bench_epoch_advance,
    bench_zone_key_derivation,
    bench_member_removal_rekey,
    bench_member_add,
    bench_memory_footprint,
    bench_compromise_recovery_full,
);
criterion_main!(benches);
