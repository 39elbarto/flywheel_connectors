//! Metamorphic tests for DurableSymbolStore::record_mutation
//! read-validate / write-publish split (br-38cd93962).
//!
//! Commit 38cd93962 split record_mutation into two scopes:
//! 1. Read-lock + validate_mutation
//! 2. WAL append + write-lock + apply_loaded_mutation
//!
//! The split shrinks the write-lock window so concurrent readers can
//! make progress during the WAL fsync. The shape preserves the
//! load-bearing guarantee that next_seq advances ONLY on a successful
//! WAL append (so a failed validate or a failed apply leaves no
//! irrecoverable gap in the WAL sequence).
//!
//! This file pins three metamorphic relations that catch any future
//! refactor that breaks the split's safety invariants:
//!
//! - **MR.read-after-write** (Equivalence): for any successful
//!   `put_symbol(s)`, a subsequent `get_symbol(s.id, s.esi)` MUST
//!   return bytes equal to `s.data`. Across a put_symbol/get_symbol
//!   round-trip the observable state matches the input.
//!
//! - **MR.failed-write-rollback-and-reload** (Invertive): a failed
//!   `put_symbol(forged)` (e.g., conflicting bytes for an existing
//!   ESI) MUST leave on-disk state byte-identical to the pre-attempt
//!   snapshot — we prove this by closing the store, REOPENING it
//!   from disk, and asserting the recovered state is the same as
//!   the pre-attempt state. Pre-fix the read-then-write split could
//!   advance next_seq on validate-success but apply-fail and leave
//!   an irrecoverable gap; the proof of "no gap" is "the store
//!   reopens cleanly and observes the same state".
//!
//! - **MR.idempotence-on-duplicate** (Equivalence): for any symbol
//!   `s`, `put_symbol(s); put_symbol(s)` (identical bytes) MUST
//!   produce the same `storage_used` and `symbol_count` as a single
//!   `put_symbol(s)`. The duplicate is an idempotent no-op at the
//!   apply layer; the WAL gets two records but the observable state
//!   is invariant under the duplicate. Pre-fix a refactor that
//!   double-counted the duplicate would inflate `used_bytes` and
//!   eventually wedge the quota check.

use bytes::Bytes;
use fcp_async_core::runtime::Runtime;
use fcp_prelude::{ObjectId, ZoneId};
use fcp_store::{
    DurableSymbolStore, DurableSymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
    StoredSymbol, SymbolMeta, SymbolStore, SymbolStoreError,
};
use proptest::prelude::*;
use tempfile::TempDir;

const SYMBOL_SIZE: u16 = 128;

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn meta_for(seed: u8, source_symbols: u32) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id: ObjectId::from_bytes([seed; 32]),
        zone_id: test_zone(),
        oti: ObjectTransmissionInfo {
            transfer_length: u64::from(SYMBOL_SIZE) * u64::from(source_symbols),
            symbol_size: SYMBOL_SIZE,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        },
        source_symbols,
        first_symbol_at: 100,
    }
}

fn symbol_for(seed: u8, esi: u32, fill: u8) -> StoredSymbol {
    StoredSymbol {
        meta: SymbolMeta {
            object_id: ObjectId::from_bytes([seed; 32]),
            esi,
            zone_id: test_zone(),
            source_node: Some(u64::from(esi).wrapping_add(1)),
            stored_at: 100 + u64::from(esi),
        },
        data: Bytes::from(vec![fill; usize::from(SYMBOL_SIZE)]),
    }
}

fn open_store(temp: &TempDir) -> DurableSymbolStore {
    let config = DurableSymbolStoreConfig::new(temp.path().join("symbols"));
    DurableSymbolStore::open(config).expect("open durable symbol store")
}

/// Snapshot of all observable state — used as the byte-for-byte
/// equality proof for the rollback MR.
#[derive(Debug, PartialEq, Eq, Clone)]
struct StateProbe {
    storage_used: u64,
    symbol_counts: Vec<(u8, u32)>,
    fetched: Vec<(u8, u32, Vec<u8>)>,
}

async fn probe(store: &DurableSymbolStore, objects: &[(u8, Vec<u32>)]) -> StateProbe {
    let storage_used = store.storage_used().await;
    let mut symbol_counts = Vec::with_capacity(objects.len());
    let mut fetched = Vec::new();
    for (seed, esis) in objects {
        let id = ObjectId::from_bytes([*seed; 32]);
        symbol_counts.push((*seed, store.symbol_count(&id).await));
        for esi in esis {
            if let Ok(sym) = store.get_symbol(&id, *esi).await {
                fetched.push((*seed, *esi, sym.data.to_vec()));
            }
        }
    }
    StateProbe {
        storage_used,
        symbol_counts,
        fetched,
    }
}

proptest! {
    /// MR.read-after-write: every successful put_symbol must be
    /// observable through get_symbol with byte-equal data. The split
    /// performs WAL append before apply; if apply ever silently
    /// failed (e.g., a refactor that swallowed apply errors) the
    /// reader would see stale state.
    #[test]
    fn mr_read_after_write_round_trips_for_arbitrary_symbol(
        seed in 1u8..=200,
        esi in 0u32..16,
        fill in 0u8..=255,
    ) {
        let temp = TempDir::new().expect("temp dir");
        let store = open_store(&temp);
        let rt = Runtime::new().expect("runtime");

        let meta = meta_for(seed, 16);
        let sym = symbol_for(seed, esi, fill);

        rt.block_on(async {
            store.put_object_meta(meta).await.expect("put meta");
            store.put_symbol(sym.clone()).await.expect("put symbol");
            let got = store
                .get_symbol(&sym.meta.object_id, sym.meta.esi)
                .await
                .expect("get_symbol after put_symbol must succeed");
            prop_assert_eq!(
                got.data.to_vec(),
                sym.data.to_vec(),
                "br-38cd93962 MR.read-after-write violated: put_symbol succeeded \
                 but get_symbol returned different bytes for object seed={} esi={}. \
                 The read-validate/write-publish split must publish the apply \
                 effects observable to subsequent reads.",
                seed,
                esi,
            );
            Ok(())
        }).unwrap();
    }

    /// MR.failed-write-rollback-and-reload: a put_symbol that fails
    /// the conflicting-bytes check MUST NOT advance next_seq, MUST
    /// NOT leave a WAL record that fails replay, and MUST NOT
    /// change the observable state. The proof: take a state probe
    /// before the failed put, attempt the failed put, take a probe
    /// after, then close + reopen the store and probe a third time.
    /// All three probes must be byte-equal.
    ///
    /// Pre-fix the original single-write-lock body could (under a
    /// refactor) advance next_seq before validate ran, leaving an
    /// irrecoverable WAL gap that load_wal_records would refuse to
    /// load on reopen — the third probe would FAIL because the
    /// store wouldn't open.
    #[test]
    fn mr_failed_validate_leaves_state_and_disk_byte_identical(
        seed in 1u8..=200,
        esi in 0u32..8,
        good_fill in 0u8..=127,
    ) {
        let bad_fill = good_fill.wrapping_add(128); // distinct bytes
        prop_assume!(good_fill != bad_fill);

        let temp = TempDir::new().expect("temp dir");
        let rt = Runtime::new().expect("runtime");
        let probe_program: Vec<(u8, Vec<u32>)> =
            vec![(seed, vec![0, 1, 2, 3, 4, 5, 6, 7])];

        let probe_program_inner = probe_program.clone();
        let (probe_before, probe_after, probe_reopen) = rt.block_on(async move {
            let store = open_store(&temp);
            store.put_object_meta(meta_for(seed, 16)).await.expect("put meta");
            store
                .put_symbol(symbol_for(seed, esi, good_fill))
                .await
                .expect("put honest symbol");

            let before = probe(&store, &probe_program_inner).await;

            // Submit a forged symbol: same ESI, conflicting bytes.
            // Must fail with InvalidSymbol per the durable
            // validate_mutation contract.
            let forged = symbol_for(seed, esi, bad_fill);
            let result = store.put_symbol(forged).await;
            prop_assert!(
                matches!(&result, Err(SymbolStoreError::InvalidSymbol { .. })),
                "br-38cd93962 MR.failed-write-rollback: forged symbol must fail \
                 with InvalidSymbol, got {:?}",
                result,
            );

            let after = probe(&store, &probe_program_inner).await;

            // Drop the store, then reopen from disk. If the failed
            // put advanced next_seq or left a corrupt WAL record,
            // this open would fail or produce a different state.
            drop(store);
            let reopened = open_store(&temp);
            let reopen = probe(&reopened, &probe_program_inner).await;
            Ok::<_, TestCaseError>((before, after, reopen))
        }).unwrap();

        prop_assert_eq!(
            &probe_before,
            &probe_after,
            "br-38cd93962 MR.failed-write-rollback: failed put_symbol changed \
             in-memory state (storage_used / symbol_count / fetched bytes)",
        );
        prop_assert_eq!(
            &probe_before,
            &probe_reopen,
            "br-38cd93962 MR.failed-write-rollback: failed put_symbol changed \
             on-disk state — store reopened with a different snapshot/WAL \
             content. The split MUST NOT advance next_seq on validate failure; \
             pre-fix this is what created an irrecoverable WAL gap that broke \
             load_wal_records on the next restart.",
        );
    }

    /// MR.idempotence-on-duplicate: put_symbol(s); put_symbol(s) for
    /// matching bytes MUST produce the same storage_used + symbol_count
    /// as a single put_symbol(s). The apply path detects byte-equal
    /// duplicates and short-circuits without re-charging used_bytes.
    /// A refactor that double-counted would inflate used_bytes and
    /// eventually trip the quota check on legitimate later writes.
    #[test]
    fn mr_idempotent_duplicate_put_does_not_inflate_storage(
        seed in 1u8..=200,
        esi in 0u32..8,
        fill in 0u8..=255,
    ) {
        let temp_single = TempDir::new().expect("temp dir single");
        let temp_double = TempDir::new().expect("temp dir double");
        let rt = Runtime::new().expect("runtime");

        let probe_program: Vec<(u8, Vec<u32>)> = vec![(seed, vec![esi])];

        let probe_program_inner = probe_program.clone();
        let (single_probe, double_probe) = rt.block_on(async move {
            let store_single = open_store(&temp_single);
            store_single.put_object_meta(meta_for(seed, 16)).await.expect("meta single");
            store_single.put_symbol(symbol_for(seed, esi, fill)).await.expect("put once");
            let single = probe(&store_single, &probe_program_inner).await;

            let store_double = open_store(&temp_double);
            store_double.put_object_meta(meta_for(seed, 16)).await.expect("meta double");
            store_double.put_symbol(symbol_for(seed, esi, fill)).await.expect("put once (of two)");
            store_double
                .put_symbol(symbol_for(seed, esi, fill))
                .await
                .expect("identical resubmission must remain idempotent at apply layer");
            let double = probe(&store_double, &probe_program_inner).await;
            (single, double)
        });

        prop_assert_eq!(
            &single_probe,
            &double_probe,
            "br-38cd93962 MR.idempotence-on-duplicate: a duplicate put_symbol \
             with byte-identical data changed observable state vs a single put. \
             The validate path returns Ok early on byte-equal existing ESI and \
             apply must not double-count used_bytes; a refactor that broke \
             either branch would inflate storage_used and eventually wedge \
             the quota check.",
        );
    }
}

/// Targeted regression: smoke floor for the rollback MR with fixed
/// inputs. Pin the failure path explicitly so a proptest config
/// shrink that misses the conflicting-bytes branch still keeps the
/// guarantee under test.
#[test]
fn mr_failed_write_smoke_floor() {
    let temp = TempDir::new().expect("temp dir");
    let rt = Runtime::new().expect("runtime");
    let probe_program: Vec<(u8, Vec<u32>)> = vec![(7u8, vec![0u32, 1])];

    rt.block_on(async {
        let store = open_store(&temp);
        store.put_object_meta(meta_for(7, 4)).await.expect("meta");
        store
            .put_symbol(symbol_for(7, 0, 0xAA))
            .await
            .expect("honest 0");
        store
            .put_symbol(symbol_for(7, 1, 0xBB))
            .await
            .expect("honest 1");
        let before = probe(&store, &probe_program).await;

        // Conflicting bytes for an already-stored ESI.
        let forged = symbol_for(7, 0, 0xCC);
        assert!(
            matches!(
                store.put_symbol(forged).await,
                Err(SymbolStoreError::InvalidSymbol { .. })
            ),
            "smoke: forged conflicting bytes must reject"
        );
        let after = probe(&store, &probe_program).await;
        assert_eq!(
            before, after,
            "smoke: failed put must not mutate in-memory state"
        );

        drop(store);
        let reopened = open_store(&temp);
        let reopen = probe(&reopened, &probe_program).await;
        assert_eq!(
            before, reopen,
            "smoke: failed put must not corrupt WAL — store reopens with same state"
        );
    });
}
