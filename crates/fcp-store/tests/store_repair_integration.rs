//! Real-component integration tests for fcp-store + fcp-raptorq.
//!
//! These tests exercise the full pipeline: encode → store → partial loss →
//! coverage evaluation → repair → reconstruct, using real `RaptorQ` encoding
//! and real in-memory stores (no mocks).
//!
//! Covers: `MemorySymbolStore`, `MemoryObjectStore`, `CoverageEvaluation`,
//! `RepairController`, `RaptorQEncoder`, `RaptorQDecoder`.

#![allow(clippy::option_if_let_else)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use fcp_core::{
    ObjectId, ObjectPlacementPolicy, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_raptorq::{RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use fcp_store::{
    CoverageEvaluation, CoverageHealth, MemoryObjectStore, MemoryObjectStoreConfig,
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectStore, ObjectSymbolMeta,
    ObjectTransmissionInfo, RepairController, RepairControllerConfig, RepairResult, StoredSymbol,
    SymbolMeta, SymbolStore,
};
use serde_json::json;
use uuid::Uuid;

// ─── Structured JSONL test harness (matches existing crate convention) ────

#[derive(Default)]
struct StoreLogData {
    object_id: Option<ObjectId>,
    object_size: Option<u64>,
    symbol_count: Option<u32>,
    coverage_bps: Option<u32>,
    nodes_holding: Option<Vec<String>>,
    details: Option<serde_json::Value>,
}

fn run_store_test<F, Fut>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
where
    F: FnOnce() -> Fut + panic::UnwindSafe,
    Fut: std::future::Future<Output = StoreLogData>,
{
    let start = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        rt.block_on(f())
    }));
    let duration_us = start.elapsed().as_micros();

    let (passed, failed, outcome, data) = match &result {
        Ok(data) => (assertions, 0, "pass", Some(data)),
        Err(_) => (0, assertions, "fail", None),
    };

    let log = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": test_name,
        "module": "fcp-store-integration",
        "phase": phase,
        "operation": operation,
        "correlation_id": Uuid::new_v4().to_string(),
        "result": outcome,
        "duration_us": duration_us,
        "object_id": data.and_then(|d| d.object_id).map(|id| id.to_string()),
        "object_size": data.and_then(|d| d.object_size),
        "symbol_count": data.and_then(|d| d.symbol_count),
        "coverage_bps": data.and_then(|d| d.coverage_bps),
        "nodes_holding": data.and_then(|d| d.nodes_holding.clone()),
        "details": data.and_then(|d| d.details.clone()),
        "assertions": {
            "passed": passed,
            "failed": failed
        }
    });
    println!("{log}");

    if let Err(payload) = result {
        panic::resume_unwind(payload);
    }
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

const fn test_raptorq_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 2000, // 20% repair overhead for meaningful repair symbol count
        max_object_size: 1024 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 1024,
        chunk_size: 256,
    }
}

fn test_zone() -> ZoneId {
    "z:integration".parse().unwrap()
}

const fn test_object_id() -> ObjectId {
    ObjectId::from_bytes([0xAB; 32])
}

/// Create a deterministic payload of the given size.
fn make_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("modulo fits u8"))
        .collect()
}

/// Encode a payload and return (symbols, OTI, `source_symbol_count`).
fn encode_payload(
    payload: &[u8],
    config: &RaptorQConfig,
) -> (
    Vec<(u32, Vec<u8>)>,
    raptorq::ObjectTransmissionInformation,
    u32,
) {
    let encoder = RaptorQEncoder::new(payload, config).expect("encode");
    let oti = encoder.transmission_info();
    let source_k = encoder.source_symbols();
    let symbols = encoder.encode_all();
    (symbols, oti, source_k)
}

/// Helper: put object meta + all given symbols into the store.
async fn store_symbols(
    store: &MemorySymbolStore,
    object_id: ObjectId,
    oti: raptorq::ObjectTransmissionInformation,
    source_k: u32,
    symbols: &[(u32, Vec<u8>)],
    node_id: u64,
) {
    let oti_ser = ObjectTransmissionInfo::from_oti(oti);
    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: test_zone(),
        oti: oti_ser,
        source_symbols: source_k,
        first_symbol_at: 1_000_000,
    };
    store.put_object_meta(meta).await.unwrap();

    for (esi, data) in symbols {
        let symbol = StoredSymbol {
            meta: SymbolMeta {
                object_id,
                esi: *esi,
                zone_id: test_zone(),
                source_node: Some(node_id),
                stored_at: 1_000_000 + u64::from(*esi),
            },
            data: Bytes::from(data.clone()),
        };
        store.put_symbol(symbol).await.unwrap();
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Full encode → store → fetch → decode roundtrip using real `RaptorQ` and
/// real `MemorySymbolStore`.
#[test]
fn encode_store_reconstruct() {
    run_store_test(
        "encode_store_reconstruct",
        "integration",
        "roundtrip",
        2,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);
            let object_id = test_object_id();

            // Encode
            let (symbols, oti, source_k) = encode_payload(&payload, &config);
            let total_symbols = symbols.len() as u32;

            // Store all symbols
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &symbols, 1).await;

            // Retrieve and decode
            let all = store.get_all_symbols(&object_id).await;
            let mut rq_decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = rq_decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("no timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            let result_data = reconstructed.expect("should reconstruct");
            assert_eq!(result_data, payload, "decoded payload must match original");
            assert!(
                store.can_reconstruct(&object_id).await,
                "store reports reconstructable"
            );

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(total_symbols),
                details: Some(json!({
                    "source_symbols": source_k,
                    "total_symbols": total_symbols,
                    "decoded_len": result_data.len(),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// After deleting some symbols the store correctly reports degraded coverage.
#[test]
fn partial_loss_degrades_coverage() {
    run_store_test(
        "partial_loss_degrades_coverage",
        "integration",
        "coverage",
        4,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &symbols, 1).await;

            // Full coverage check
            let dist_full = store.get_distribution(&object_id).await.unwrap();
            let eval_full = CoverageEvaluation::from_distribution(object_id, &dist_full);
            assert!(eval_full.is_available, "initially available");
            assert!(eval_full.coverage_bps >= 10000, "initial coverage >= 100%");

            // Delete half the symbols to simulate partial loss
            let esis_to_delete: Vec<u32> = symbols
                .iter()
                .take(symbols.len() / 2)
                .map(|(esi, _)| *esi)
                .collect();
            for esi in &esis_to_delete {
                store.delete_symbol(&object_id, *esi).await.unwrap();
            }

            // Degraded coverage check
            let dist_after = store.get_distribution(&object_id).await.unwrap();
            let eval_after = CoverageEvaluation::from_distribution(object_id, &dist_after);
            assert!(
                eval_after.coverage_bps < eval_full.coverage_bps,
                "coverage dropped after loss"
            );

            let policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };
            let health = eval_after.health(&policy);
            assert!(
                health != CoverageHealth::Healthy,
                "health should not be Healthy after loss"
            );

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist_after.total_symbols),
                coverage_bps: Some(eval_after.coverage_bps),
                details: Some(json!({
                    "coverage_before_bps": eval_full.coverage_bps,
                    "coverage_after_bps": eval_after.coverage_bps,
                    "symbols_deleted": esis_to_delete.len(),
                    "health": format!("{health:?}"),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Full pipeline: encode → store → lose symbols → repair adds new symbols →
/// verify reconstruction succeeds.
#[test]
#[allow(clippy::too_many_lines)]
fn partial_loss_repair_reconstruct() {
    run_store_test(
        "partial_loss_repair_reconstruct",
        "integration",
        "repair",
        3,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640); // 10 source symbols × 64 bytes
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);
            let total_encoded = symbols.len() as u32;

            // Store only source symbols (not repair) to leave room for repair later
            let source_only: Vec<_> = symbols
                .iter()
                .filter(|(esi, _)| *esi < source_k)
                .cloned()
                .collect();

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &source_only, 1).await;

            // Delete some source symbols to simulate loss
            let delete_count = (source_k / 3).max(1);
            for esi in 0..delete_count {
                store.delete_symbol(&object_id, esi).await.unwrap();
            }

            // Verify not reconstructable
            let remaining = store.symbol_count(&object_id).await;
            assert!(
                remaining < source_k,
                "fewer symbols than K after deletion: {remaining} < {source_k}"
            );

            // Re-encode to get repair symbols (simulates what a repair peer would do)
            let (repair_symbols, _, _) = encode_payload(&payload, &config);
            let repair_only: Vec<_> = repair_symbols
                .iter()
                .filter(|(esi, _)| *esi >= source_k)
                .cloned()
                .collect();

            // Add repair symbols to fill the gap
            for (esi, data) in &repair_only {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi: *esi,
                        zone_id: test_zone(),
                        source_node: Some(2), // Different node
                        stored_at: 2_000_000 + u64::from(*esi),
                    },
                    data: Bytes::from(data.clone()),
                };
                store.put_symbol(symbol).await.unwrap();
            }

            // Also re-add some deleted source symbols from a "repair peer"
            // (we need at least K' ≈ K symbols total to reconstruct)
            let need_more = source_k.saturating_sub(store.symbol_count(&object_id).await);
            for esi in 0..need_more {
                let matching: Option<&(u32, Vec<u8>)> = symbols.iter().find(|(e, _)| *e == esi);
                if let Some((e, d)) = matching {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi: *e,
                            zone_id: test_zone(),
                            source_node: Some(3),
                            stored_at: 3_000_000 + u64::from(*e),
                        },
                        data: Bytes::from(d.clone()),
                    };
                    store.put_symbol(symbol).await.unwrap();
                }
            }

            // Reconstruct
            let all = store.get_all_symbols(&object_id).await;
            let mut rq_decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = rq_decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("no timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            let result_data = reconstructed.expect("should reconstruct after repair");
            assert_eq!(result_data, payload, "repaired payload matches original");

            let dist = store.get_distribution(&object_id).await.unwrap();
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({
                    "source_k": source_k,
                    "total_encoded": total_encoded,
                    "deleted": delete_count,
                    "repair_added": repair_only.len(),
                    "final_count": dist.total_symbols,
                    "reconstructed": true,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// `RepairController` detects degraded coverage and queues repair; after adding
/// symbols, coverage converges to the target and the queue empties.
#[test]
#[allow(clippy::too_many_lines)]
fn repair_controller_drives_convergence() {
    run_store_test(
        "repair_controller_drives_convergence",
        "integration",
        "repair",
        4,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });

            // Store only half the source symbols → under-covered
            let half = (source_k / 2) as usize;
            let partial: Vec<_> = symbols.iter().take(half).cloned().collect();
            store_symbols(&store, object_id, oti, source_k, &partial, 1).await;

            let policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };

            let controller = RepairController::new(RepairControllerConfig {
                min_deficit_bps: 100,
                max_symbols_per_repair: 20,
                ..Default::default()
            });

            let mut policies = HashMap::new();
            policies.insert(object_id, policy.clone());

            // Evaluate zone — should queue a repair
            controller
                .evaluate_zone(&test_zone(), &store, &policies)
                .await;
            let initial_depth = controller.queue_depth();
            assert!(initial_depth > 0, "repair should be queued");

            // Simulate repair: take from queue, add symbols
            if let Some(request) = controller.next_repair() {
                let needed = request
                    .coverage
                    .symbols_needed(request.policy.target_coverage_bps);
                let to_add = needed.min(controller.config().max_symbols_per_repair);

                // Re-encode to get fresh symbols
                let (fresh_symbols, _, _) = encode_payload(&payload, &config);

                // Use symbols the store doesn't already have
                let mut added = 0_u32;
                for (esi, data) in &fresh_symbols {
                    if added >= to_add {
                        break;
                    }
                    if store.get_symbol(&object_id, *esi).await.is_err() {
                        let symbol = StoredSymbol {
                            meta: SymbolMeta {
                                object_id,
                                esi: *esi,
                                zone_id: test_zone(),
                                source_node: Some(2),
                                stored_at: 2_000_000 + u64::from(*esi),
                            },
                            data: Bytes::from(data.clone()),
                        };
                        store.put_symbol(symbol).await.unwrap();
                        added += 1;
                    }
                }

                let dist = store.get_distribution(&object_id).await.unwrap();
                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                controller.record_result(&RepairResult {
                    object_id,
                    success: true,
                    new_coverage_bps: eval.coverage_bps,
                    symbols_added: added,
                    error: None,
                });
            }

            // Re-evaluate — queue should be empty now
            controller
                .evaluate_zone(&test_zone(), &store, &policies)
                .await;

            let dist_final = store.get_distribution(&object_id).await.unwrap();
            let eval_final = CoverageEvaluation::from_distribution(object_id, &dist_final);

            assert!(
                eval_final.coverage_bps >= policy.target_coverage_bps,
                "coverage should meet target: {} >= {}",
                eval_final.coverage_bps,
                policy.target_coverage_bps,
            );
            assert_eq!(controller.queue_depth(), 0, "queue empty after convergence");

            let stats = controller.stats();
            assert!(
                stats.repairs_succeeded >= 1,
                "at least one repair succeeded"
            );

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist_final.total_symbols),
                coverage_bps: Some(eval_final.coverage_bps),
                details: Some(json!({
                    "initial_queue_depth": initial_depth,
                    "final_queue_depth": controller.queue_depth(),
                    "repairs_attempted": stats.repairs_attempted,
                    "repairs_succeeded": stats.repairs_succeeded,
                    "symbols_added": stats.symbols_added,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Object store and symbol store work together: store a complete object and
/// its symbols, verify both are accessible and coverage is healthy.
#[test]
#[allow(clippy::too_many_lines)]
fn object_and_symbol_stores_coherent() {
    run_store_test(
        "object_and_symbol_stores_coherent",
        "integration",
        "roundtrip",
        5,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(384);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            // Object store: store the complete object
            let obj_store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let stored_obj = StoredObject {
                object_id,
                header: fcp_core::ObjectHeader {
                    schema: fcp_cbor::SchemaId::new(
                        "fcp.test",
                        "IntegrationTest",
                        semver::Version::new(1, 0, 0),
                    ),
                    zone_id: test_zone(),
                    created_at: 1_000_000,
                    provenance: Provenance::new(test_zone()),
                    refs: vec![],
                    foreign_refs: vec![],
                    ttl_secs: None,
                    placement: None,
                },
                body: payload.clone(),
                storage: StorageMeta {
                    retention: RetentionClass::Pinned,
                },
            };
            obj_store.put(stored_obj).await.unwrap();

            // Symbol store: store all encoded symbols
            let sym_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&sym_store, object_id, oti, source_k, &symbols, 1).await;

            // Verify object store has the object
            let retrieved = obj_store.get(&object_id).await.unwrap();
            assert_eq!(retrieved.body, payload, "object store body matches");

            // Verify symbol store has all symbols
            let sym_count = sym_store.symbol_count(&object_id).await;
            assert_eq!(
                sym_count,
                symbols.len() as u32,
                "symbol count matches encoded"
            );

            // Verify symbol store reports reconstructable
            assert!(
                sym_store.can_reconstruct(&object_id).await,
                "can reconstruct from symbols"
            );

            // Verify coverage is healthy
            let dist = sym_store.get_distribution(&object_id).await.unwrap();
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);
            assert!(eval.is_available, "coverage reports available");

            let policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };
            assert!(eval.meets_policy(&policy), "meets placement policy");

            // Verify retention class persisted correctly
            let storage_meta = obj_store.get_storage_meta(&object_id).await.unwrap();
            assert!(
                matches!(storage_meta.retention, RetentionClass::Pinned),
                "retention is Pinned"
            );

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(sym_count),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({
                    "source_k": source_k,
                    "total_symbols": symbols.len(),
                    "retention": "Pinned",
                    "is_available": eval.is_available,
                    "meets_policy": eval.meets_policy(&policy),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Multi-node distribution: symbols spread across multiple nodes should
/// report correct `distinct_nodes` and `max_node_fraction` in coverage.
#[test]
fn multi_node_symbol_distribution() {
    run_store_test(
        "multi_node_symbol_distribution",
        "integration",
        "placement",
        4,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });

            let oti_ser = ObjectTransmissionInfo::from_oti(oti);
            let meta = ObjectSymbolMeta {
                object_id,
                zone_id: test_zone(),
                oti: oti_ser,
                source_symbols: source_k,
                first_symbol_at: 1_000_000,
            };
            store.put_object_meta(meta).await.unwrap();

            // Distribute symbols across 3 nodes in round-robin
            for (i, (esi, data)) in symbols.iter().enumerate() {
                let node_id = (i % 3) as u64 + 1; // nodes 1, 2, 3
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi: *esi,
                        zone_id: test_zone(),
                        source_node: Some(node_id),
                        stored_at: 1_000_000 + u64::from(*esi),
                    },
                    data: Bytes::from(data.clone()),
                };
                store.put_symbol(symbol).await.unwrap();
            }

            let dist = store.get_distribution(&object_id).await.unwrap();
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 3, "3 distinct nodes");
            assert!(eval.is_available, "available with all symbols");

            // Max fraction should be roughly 1/3 (3333 bps) since round-robin
            // but off-by-one in distribution is possible
            assert!(
                eval.max_node_fraction_bps <= 5000,
                "no single node has > 50% of symbols: {}",
                eval.max_node_fraction_bps
            );

            let policy = ObjectPlacementPolicy {
                min_nodes: 3,
                max_node_fraction_bps: 5000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };
            assert!(eval.meets_policy(&policy), "meets 3-node policy");

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(vec!["node-1".into(), "node-2".into(), "node-3".into()]),
                details: Some(json!({
                    "distinct_nodes": eval.distinct_nodes,
                    "max_node_fraction_bps": eval.max_node_fraction_bps,
                    "total_symbols": dist.total_symbols,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Verify that encoding + decoding works with only repair symbols
/// (no source symbols present), demonstrating fountain code properties.
#[test]
fn reconstruct_from_repair_symbols_only() {
    run_store_test(
        "reconstruct_from_repair_symbols_only",
        "integration",
        "decode",
        1,
        || async {
            let config = RaptorQConfig {
                symbol_size: 64,
                repair_ratio_bps: 10000, // 100% repair overhead = K repair symbols
                max_object_size: 1024 * 1024,
                decode_timeout: Duration::from_secs(30),
                max_chunk_threshold: 1024,
                chunk_size: 256,
            };
            let payload = make_payload(384); // 6 source symbols
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            // Keep only repair symbols (ESI >= source_k)
            let repair_only: Vec<_> = symbols
                .iter()
                .filter(|(esi, _)| *esi >= source_k)
                .cloned()
                .collect();

            assert!(
                !repair_only.is_empty(),
                "must have repair symbols for this test"
            );

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &repair_only, 1).await;

            // Attempt decode using only repair symbols
            let all = store.get_all_symbols(&object_id).await;
            let mut rq_decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = rq_decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("no timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            // Fountain code property: repair symbols alone should reconstruct
            // if we have enough (≈ K' symbols)
            let success = reconstructed.as_ref().is_some_and(|d| *d == payload);

            // Note: with K repair symbols, reconstruction should generally succeed
            // since RaptorQ needs K' ≈ K×1.002. With 100% overhead we have K repair
            // symbols which equals K, which is nearly always sufficient.
            assert!(success, "reconstructed from repair symbols only");

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(repair_only.len() as u32),
                details: Some(json!({
                    "source_k": source_k,
                    "repair_only_count": repair_only.len(),
                    "reconstructed": success,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// OTI round-trip: `ObjectTransmissionInfo` converts losslessly between
/// the fcp-store serializable form and raptorq's native form.
#[test]
fn oti_roundtrip_fidelity() {
    run_store_test(
        "oti_roundtrip_fidelity",
        "integration",
        "oti",
        5,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);

            let encoder = RaptorQEncoder::new(&payload, &config).expect("encode");
            let oti_native = encoder.transmission_info();

            // Convert to serializable form
            let oti_ser = ObjectTransmissionInfo::from_oti(oti_native);

            // Convert back
            let oti_back = oti_ser.to_oti();

            // Verify all fields match
            assert_eq!(
                oti_native.transfer_length(),
                oti_back.transfer_length(),
                "transfer_length"
            );
            assert_eq!(
                oti_native.symbol_size(),
                oti_back.symbol_size(),
                "symbol_size"
            );
            assert_eq!(
                oti_native.source_blocks(),
                oti_back.source_blocks(),
                "source_blocks"
            );
            assert_eq!(oti_native.sub_blocks(), oti_back.sub_blocks(), "sub_blocks");
            assert_eq!(
                oti_native.symbol_alignment(),
                oti_back.symbol_alignment(),
                "alignment"
            );

            StoreLogData {
                object_size: Some(payload.len() as u64),
                details: Some(json!({
                    "transfer_length": oti_ser.transfer_length,
                    "symbol_size": oti_ser.symbol_size,
                    "source_blocks": oti_ser.source_blocks,
                    "sub_blocks": oti_ser.sub_blocks,
                    "alignment": oti_ser.alignment,
                })),
                ..StoreLogData::default()
            }
        },
    );
}
