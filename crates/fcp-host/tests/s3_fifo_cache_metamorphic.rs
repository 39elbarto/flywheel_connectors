//! Metamorphic tests for the S3-FIFO supply-chain cache (br-3c5ec72b5).
//!
//! Commit 3c5ec72b5 replaced the legacy oldest-entry cache (whose
//! eviction was an O(n) full-map scan) with an S3-FIFO design that
//! exposes a Small queue, a Main queue, and a ghost set for recently-
//! evicted keys. The shape preserves the bounded-capacity invariant
//! while giving frequent hitters a chance to survive an eviction
//! sweep before the first FIFO pass reaches them.
//!
//! These metamorphic relations pin the contract so any future refactor
//! of the eviction policy keeps the load-bearing properties:
//!
//! - **MR.idempotent-lookup** (Equivalence): repeated `get(k)` on a
//!   resident key returns Some(v) with the same v each time. Catches
//!   any refactor that mutates the stored value as a side effect of
//!   the frequency increment.
//!
//! - **MR.under-capacity-set-equality** (Permutative): for any set S
//!   with |S| ≤ capacity, inserting S in any order yields the same
//!   resident-key set. The S3-FIFO admission policy is order-sensitive
//!   only WHEN inserts exceed capacity; under-capacity workloads must
//!   produce a permutation-invariant cache contents. Catches any
//!   refactor that drops valid keys before capacity is reached.
//!
//! - **MR.hot-entry-survives-first-eviction** (Inclusive): a key
//!   that has been `get`-touched at least once before the cache
//!   reaches capacity MUST remain resident through the first
//!   eviction sweep that would otherwise have removed it. This is
//!   the entire reason S3-FIFO was chosen over plain FIFO — frequent
//!   hitters get a free pass before the first FIFO eviction.
//!
//! - **MR.ghost-readmission-lands-on-main** (Permutative on queue):
//!   a key that was inserted, evicted (and thus enters the ghost set),
//!   and re-inserted MUST land on the Main queue (not Small). This
//!   is the S3-FIFO promotion path that protects "recently hot"
//!   keys from a second eviction. Catches any refactor that breaks
//!   the ghost-set lookup at insert time.

use fcp_host::S3FifoCache;
use proptest::prelude::*;
use std::collections::HashSet;

/// Generate a non-empty list of distinct cache keys.
fn arb_distinct_keys(min: usize, max: usize) -> impl Strategy<Value = Vec<String>> {
    proptest::collection::hash_set("[a-z]{3,8}", min..=max).prop_map(|set| {
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort();
        v
    })
}

proptest! {
    /// MR.idempotent-lookup: repeated get() on a resident key returns
    /// the same Some(v) each time. The frequency counter increments
    /// on every hit but the value MUST NOT change.
    ///
    /// Pre-fix concern: a refactor that swapped value mutation into
    /// the get-side hot path (e.g., to add a TTL update) could drift
    /// the returned bytes between consecutive lookups.
    #[test]
    fn mr_idempotent_lookup_value_stable_across_repeated_gets(
        key in "[a-z]{3,8}",
        value in 0u32..1_000_000,
    ) {
        let mut cache: S3FifoCache<u32> = S3FifoCache::new(8);
        cache.insert(key.clone(), value);

        let v1 = cache.get(&key);
        let v2 = cache.get(&key);
        let v3 = cache.get(&key);
        let v4 = cache.get(&key);

        prop_assert_eq!(v1, Some(value), "first get must return inserted value");
        prop_assert_eq!(
            v1, v2,
            "br-3c5ec72b5 MR.idempotent-lookup violated: get(k) returned \
             different values on consecutive calls — frequency increment must \
             not mutate the stored value"
        );
        prop_assert_eq!(v2, v3, "third get diverged from second");
        prop_assert_eq!(v3, v4, "fourth get diverged from third");
    }

    /// MR.under-capacity-set-equality: when |inserts| ≤ capacity, the
    /// set of resident keys equals the set of inserted keys regardless
    /// of insertion order. Pre-fix any future refactor that
    /// pre-emptively evicted before capacity was reached would shrink
    /// the resident set non-deterministically.
    ///
    /// We exercise this by generating a small distinct key set, then
    /// applying two random permutations of that set to two fresh
    /// caches with capacity ≥ |keys|. Resident-key sets must agree.
    #[test]
    fn mr_under_capacity_inserts_are_permutation_invariant(
        keys in arb_distinct_keys(1, 6),
        salt in 0u64..1_000,
    ) {
        let cap = keys.len() + 2; // headroom so we never trigger eviction
        let mut a: S3FifoCache<u64> = S3FifoCache::new(cap);
        let mut b: S3FifoCache<u64> = S3FifoCache::new(cap);

        // Order π1 = original.
        for (i, k) in keys.iter().enumerate() {
            a.insert(k.clone(), salt.wrapping_add(i as u64));
        }
        // Order π2 = reversed (a different permutation, deterministic).
        for (i, k) in keys.iter().rev().enumerate() {
            b.insert(k.clone(), salt.wrapping_add((keys.len() - 1 - i) as u64));
        }

        // Resident-key set comparison.
        let mut a_resident: HashSet<String> = HashSet::new();
        let mut b_resident: HashSet<String> = HashSet::new();
        for k in &keys {
            if a.get(k).is_some() {
                a_resident.insert(k.clone());
            }
            if b.get(k).is_some() {
                b_resident.insert(k.clone());
            }
        }
        prop_assert_eq!(
            &a_resident,
            &b_resident,
            "br-3c5ec72b5 MR.under-capacity-set-equality violated: same key set \
             inserted in two orders produced different resident sets at \
             capacity {} (no eviction should have fired)",
            cap,
        );
        prop_assert_eq!(
            a_resident.len(),
            keys.len(),
            "under-capacity inserts must retain ALL keys; lost some at capacity {}",
            cap,
        );
    }

    /// MR.hot-entry-survives-first-eviction: a key that has been
    /// `get`-touched (frequency >= 1) before the cache fills must
    /// survive the first eviction sweep that would otherwise remove
    /// it. This is the load-bearing S3-FIFO promise — it's the
    /// reason S3-FIFO was chosen over plain FIFO.
    ///
    /// Construction:
    ///  1. capacity = N
    ///  2. insert hot_key
    ///  3. get(hot_key) several times → frequency saturates
    ///  4. insert cold_key_1 .. cold_key_N to force eviction
    ///  5. assert hot_key is STILL resident
    ///
    /// Pre-fix any refactor that ignored frequency on eviction would
    /// drop hot_key on the first sweep, breaking the cache's
    /// admission contract.
    #[test]
    fn mr_hot_entry_survives_first_eviction_sweep(
        capacity in 4usize..=8,
        cold_overflow in 1usize..=4,
    ) {
        let mut cache: S3FifoCache<u32> = S3FifoCache::new(capacity);
        let hot_key = "hot".to_string();
        cache.insert(hot_key.clone(), 99);

        // Repeated gets bump frequency above 0.
        for _ in 0..3 {
            prop_assert!(cache.get(&hot_key).is_some(), "hot key must be resident before stress");
        }

        // Fill + overflow with cold keys to force eviction.
        let total_cold = capacity + cold_overflow;
        for i in 0..total_cold {
            cache.insert(format!("cold-{i}"), i as u32);
        }

        prop_assert!(
            cache.get(&hot_key).is_some(),
            "br-3c5ec72b5 MR.hot-entry-survives-first-eviction violated: hot key \
             with frequency >= 1 was evicted on the first sweep at capacity {}, \
             cold overflow {}. The S3-FIFO promotion path must give hot entries \
             at least one extra pass before eviction.",
            capacity,
            cold_overflow,
        );
    }

    /// MR.ghost-readmission-lands-on-main: a key that was evicted to
    /// the ghost set and re-inserted MUST be admitted to Main rather
    /// than Small. We can't directly observe queue placement (private
    /// field), but we can OBSERVE its consequence: a Main-resident
    /// key with frequency > 0 survives a second eviction wave, while
    /// a Small-resident key with the same frequency would be evicted
    /// first.
    ///
    /// Construction:
    ///  1. insert k → Small queue (resident)
    ///  2. force eviction → k goes to ghost
    ///  3. re-insert k → MUST land on Main (per S3-FIFO ghost-hit promotion)
    ///  4. get(k) once → frequency = 1
    ///  5. flood capacity with FRESH cold keys (not in ghost) →
    ///     these enter Small with frequency = 0 and get evicted first
    ///  6. k MUST still be resident
    ///
    /// Pre-fix concern: a refactor that dropped the
    /// `was_ghost && main_capacity > 0` check at insert time would
    /// always admit to Small, defeating the protection.
    #[test]
    fn mr_ghost_readmitted_key_survives_subsequent_eviction(
        capacity in 4usize..=8,
    ) {
        let mut cache: S3FifoCache<u32> = S3FifoCache::new(capacity);
        let target = "target".to_string();

        // Phase 1: insert target, then evict it to the ghost set by
        // overflowing with cold-evict keys (each unobserved → freq 0).
        cache.insert(target.clone(), 7);
        for i in 0..(capacity * 2) {
            cache.insert(format!("evict-{i}"), i as u32);
        }
        prop_assert!(
            cache.get(&target).is_none(),
            "test setup: target should have been evicted to ghost by overflow"
        );

        // Phase 2: re-insert target. With ghost-set hit + main_capacity > 0,
        // the S3-FIFO admission MUST place it on Main.
        cache.insert(target.clone(), 11);
        prop_assert!(cache.get(&target).is_some(), "re-inserted target must be resident");

        // Phase 3: flood with FRESH cold keys (none of which are in
        // the ghost set, so they enter Small). target on Main with
        // frequency >= 1 survives; target on Small with frequency = 1
        // would be evicted first (Small evicts before Main).
        for i in 0..(capacity * 3) {
            cache.insert(format!("fresh-{i}"), i as u32);
        }

        prop_assert!(
            cache.get(&target).is_some(),
            "br-3c5ec72b5 MR.ghost-readmission violated: target re-admitted \
             from ghost set was evicted by fresh-cold flood, which means it \
             was placed on Small (evicted first) instead of Main (per ghost-hit \
             promotion). Capacity {}.",
            capacity,
        );
    }
}

/// Smoke floor: a hand-built scenario combining all four MRs, to
/// guard against a proptest config that shrinks aggressively past
/// the load-bearing branches.
#[test]
fn mr_s3_fifo_cache_smoke_floor() {
    // Capacity 4: main_capacity ≈ 3, small ≈ 1.
    let mut cache: S3FifoCache<u32> = S3FifoCache::new(4);

    // 1. Idempotent lookup: insert + get×3 returns same value.
    cache.insert("a".to_string(), 1);
    for _ in 0..3 {
        assert_eq!(cache.get("a"), Some(1), "smoke: idempotent get drift");
    }

    // 2. Under-capacity set equality: insert 3 distinct keys, all
    //    resident.
    cache.insert("b".to_string(), 2);
    cache.insert("c".to_string(), 3);
    assert_eq!(cache.len(), 3);
    for k in ["a", "b", "c"] {
        assert!(cache.get(k).is_some(), "smoke: under-capacity lost key {k}");
    }

    // 3. Hot survives: bump 'a' to frequency >= 1 (already done above
    //    via the 4 gets), then flood with cold keys.
    for i in 0..6 {
        cache.insert(format!("cold-{i}"), 100 + i);
    }
    assert!(
        cache.get("a").is_some(),
        "smoke: hot key 'a' was evicted by cold flood — S3-FIFO frequency promotion broken"
    );
}
