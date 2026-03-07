use std::collections::HashMap;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fcp_core::{ObjectId, ObjectPlacementPolicy, ZoneId};
use fcp_store::{
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
    RepairController, RepairControllerConfig, RepairCycleBudget, RepairPlanningOptions,
    StoredSymbol, SymbolMeta, SymbolStore,
};

fn bench_zone() -> ZoneId {
    "z:bench".parse().unwrap()
}

#[allow(clippy::missing_const_for_fn)]
fn bench_policy() -> ObjectPlacementPolicy {
    ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 10_000,
        min_source_diversity: 0,
    }
}

fn populate_fixture(
    object_count: usize,
) -> (
    RepairController,
    MemorySymbolStore,
    ZoneId,
    HashMap<ObjectId, ObjectPlacementPolicy>,
    RepairPlanningOptions,
) {
    let zone_id = bench_zone();
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
        max_bytes: 512 * 1024 * 1024,
        local_node_id: 1,
    });

    let mut policies = HashMap::new();

    fcp_async_core::runtime::block_on_sync(async {
        for index in 0..object_count {
            let bytes = index.to_le_bytes();
            let mut raw_id = [0_u8; 32];
            raw_id[..bytes.len()].copy_from_slice(&bytes);
            raw_id[31] = 1;
            let object_id = ObjectId::from_bytes(raw_id);

            store
                .put_object_meta(ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: 32,
                        symbol_size: 8,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols: 4,
                    first_symbol_at: 1_000_000,
                })
                .await
                .unwrap();

            for esi in 0..3 {
                store
                    .put_symbol(StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(u64::from(u32::try_from(index % 3).unwrap() + 1)),
                            stored_at: 1_000_000 + u64::from(esi),
                        },
                        data: Bytes::from(vec![0_u8; 8]),
                    })
                    .await
                    .unwrap();
            }

            policies.insert(object_id, bench_policy());
        }
    })
    .expect("runtime");

    let controller = RepairController::new(RepairControllerConfig {
        min_deficit_bps: 100,
        max_symbols_per_repair: 4,
        ..Default::default()
    });
    let options = RepairPlanningOptions {
        cycle_id: 1,
        budget: RepairCycleBudget {
            max_repairs: object_count,
            max_bytes: u64::MAX,
            max_decode_ms: u32::MAX,
        },
        derp_penalty_bps: 2_500,
        ..Default::default()
    };

    (controller, store, zone_id, policies, options)
}

fn bench_repair_controller(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_controller_plan_zone");

    for object_count in [1_000usize, 10_000, 100_000] {
        let (controller, store, zone_id, policies, options) = populate_fixture(object_count);
        group.bench_with_input(
            BenchmarkId::from_parameter(object_count),
            &object_count,
            |b, _| {
                b.iter(|| {
                    fcp_async_core::runtime::block_on_sync(
                        controller.plan_zone(&zone_id, &store, &policies, &options),
                    )
                    .expect("runtime")
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_repair_controller);
criterion_main!(benches);
