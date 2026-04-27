#![no_main]

//! Fuzz target for `fcp_store::QuarantineStore` eviction priority +
//! TTL freshness parity (quarantine.rs:144-498).
//!
//! Two non-trivial invariants:
//!
//!   - Eviction ordering (EvictionEntry::cmp at quarantine.rs:99-115):
//!     oldest-first → lowest-reputation → largest-size — when quota
//!     forces eviction, the worst entry must evict first.
//!   - Read/sweep TTL parity (closed by bead flywheel_connectors-dzhhq):
//!     get_fresh and evict_expired use the SAME staleness rule
//!     (now - received_at > ttl_secs). A regression where one path
//!     uses `>=` while the other uses `>` (or different units) would
//!     let stale admission state leak between sweep cycles.
//!
//! Existing fcp-store fuzz coverage does NOT touch QuarantineStore.
//!
//! Properties asserted:
//!
//!   1. **quarantine then contains**: a successfully quarantined
//!      object MUST appear via `contains` until removed/evicted.
//!   2. **Idempotent re-quarantine**: same object_id twice MUST
//!      succeed Ok without re-counting bytes.
//!   3. **remove inverse**: quarantine then remove returns the
//!      object; second remove returns NotFound.
//!   4. **get_fresh / evict_expired parity (dzhhq)**: get_fresh
//!      returns None ⇔ now - received_at > ttl. After evict_expired
//!      with the same time, get also returns None.
//!   5. **Eviction ordering**: when quota forces eviction, OLDEST
//!      received_at goes first.
//!   6. **Quota cap enforcement**: zone_stats.used_bytes never
//!      exceeds max_quarantine_bytes_per_zone.
//!
//!   Once-gated regression anchors:
//!     (a) get_fresh strictly older than ttl returns None even before
//!         evict_expired runs (dzhhq parity).
//!     (b) Quota-eviction ordering: 3 entries with received_at
//!         10/20/30 (small bytes cap), inserting a 4th evicts
//!         received_at=10 first.
//!     (c) Idempotent quarantine: same id twice → contains true,
//!         used_bytes equals data.len() once.

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use fcp_core::{ObjectId, ZoneId};
use fcp_store::{ObjectAdmissionPolicy, QuarantineError, QuarantineStore, QuarantinedObject};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_OPS: usize = 16;

static QUARANTINE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    received_at: u32,
    obj_seed: u8,
    /// Time relative to received_at, used to probe fresh/stale boundary.
    query_offset: i32,
    /// Apply remove on this iteration.
    do_remove: bool,
    /// Number of ops to apply.
    op_count: u8,
}

fn small_policy() -> ObjectAdmissionPolicy {
    ObjectAdmissionPolicy {
        max_quarantine_bytes_per_zone: 1024,
        max_quarantine_objects_per_zone: 8,
        quarantine_ttl_secs: 100,
        require_schema_validation: false,
    }
}

fn make_obj(seed: u8, received_at: u64, size: usize) -> QuarantinedObject {
    let mut id_bytes = [0u8; 32];
    id_bytes[0] = seed;
    QuarantinedObject {
        object_id: ObjectId::from_bytes(id_bytes),
        zone_id: ZoneId::work(),
        data: Bytes::from(vec![seed; size]),
        source_peer: None,
        received_at,
        peer_reputation: 0,
    }
}

fuzz_target!(|data: &[u8]| {
    QUARANTINE_ANCHOR.call_once(assert_quarantine_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let store = QuarantineStore::new(small_policy());
    let received_at = u64::from(input.received_at) % 10_000;
    let obj = make_obj(input.obj_seed, received_at, 32);
    let oid = obj.object_id;

    // ── PROPERTY 1: quarantine then contains ──────────────────────────
    let q_result = store.quarantine(obj.clone());
    if q_result.is_ok() {
        assert!(
            store.contains(&oid),
            "object {oid:?} successfully quarantined but contains() returns false"
        );
    }

    // ── PROPERTY 2: idempotent re-quarantine ──────────────────────────
    if q_result.is_ok() {
        let again = store.quarantine(obj.clone());
        assert!(
            again.is_ok(),
            "re-quarantine of same object_id failed: {again:?}"
        );
        assert!(
            store.contains(&oid),
            "object missing after idempotent re-quarantine"
        );
    }

    // ── PROPERTY 4: get_fresh parity ──────────────────────────────────
    if q_result.is_ok() {
        // Compute query time = received_at + offset (saturating).
        let query_time = if input.query_offset >= 0 {
            received_at.saturating_add(input.query_offset as u64)
        } else {
            received_at.saturating_sub(input.query_offset.unsigned_abs() as u64)
        };
        let staleness = query_time.saturating_sub(received_at);
        let ttl = small_policy().quarantine_ttl_secs;
        let expected_fresh = staleness <= ttl;

        let got = store.get_fresh(&oid, query_time);
        if expected_fresh {
            assert!(
                got.is_some(),
                "get_fresh returned None for fresh entry: staleness={staleness}, ttl={ttl}"
            );
        } else {
            assert!(
                got.is_none(),
                "get_fresh returned Some for stale entry: staleness={staleness}, ttl={ttl} \
                 — read-path freshness rule disagrees with sweep-path"
            );
        }
    }

    // ── PROPERTY 3: remove inverse ────────────────────────────────────
    if input.do_remove && q_result.is_ok() {
        let removed = store.remove(&oid);
        assert!(
            removed.is_ok(),
            "remove of just-quarantined object failed: {removed:?}"
        );
        // Second remove MUST return NotFound.
        match store.remove(&oid) {
            Err(QuarantineError::NotFound(_)) => {}
            other => panic!("second remove returned {other:?}; expected NotFound"),
        }
    }

    // ── PROPERTY 6: quota cap enforcement (multi-op stress) ───────────
    let store2 = QuarantineStore::new(small_policy());
    let n = (input.op_count as usize) % MAX_OPS;
    for i in 0..n {
        let o = make_obj((i as u8).wrapping_add(0x40), received_at + i as u64, 64);
        let _ = store2.quarantine(o);
    }
    let stats = store2.zone_stats(&ZoneId::work());
    assert!(
        stats.used_bytes <= small_policy().max_quarantine_bytes_per_zone,
        "zone used_bytes ({}) > policy cap ({}) after {n} ops",
        stats.used_bytes,
        small_policy().max_quarantine_bytes_per_zone
    );
});

/// Once-gated regression anchors for the most load-bearing quarantine
/// invariants.
fn assert_quarantine_anchored() {
    let policy = small_policy();
    let ttl = policy.quarantine_ttl_secs;

    // (a) get_fresh strictly older than ttl returns None even without
    // evict_expired (dzhhq parity).
    let store = QuarantineStore::new(policy.clone());
    let obj = make_obj(0xAA, 100, 32);
    let oid = obj.object_id;
    store.quarantine(obj).expect("anchor quarantine");

    // Same time → fresh.
    assert!(
        store.get_fresh(&oid, 100).is_some(),
        "ANCHOR: same-time get_fresh returned None"
    );

    // ttl seconds later → still fresh (boundary is `>`).
    assert!(
        store.get_fresh(&oid, 100 + ttl).is_some(),
        "ANCHOR: get_fresh at exactly received_at + ttl returned None; \
         staleness rule should be `>`, not `>=`"
    );

    // ttl + 1 seconds later → stale.
    assert!(
        store.get_fresh(&oid, 100 + ttl + 1).is_none(),
        "ANCHOR REGRESSION: get_fresh past ttl returned Some — read-path \
         freshness rule disagrees with evict_expired sweep rule (dzhhq \
         regression: stale admission state leaks indefinitely between \
         sweep cycles)"
    );

    // (b) Quota-eviction ordering: 3 small entries, then a 4th forces
    // oldest (received_at=10) to evict first.
    let cap = ObjectAdmissionPolicy {
        max_quarantine_bytes_per_zone: 100, // tight: 3 × 30 = 90 fits, 4th evicts
        max_quarantine_objects_per_zone: 100,
        quarantine_ttl_secs: 1_000_000,
        require_schema_validation: false,
    };
    let store = QuarantineStore::new(cap.clone());
    let oldest = make_obj(0x10, 10, 30);
    let mid = make_obj(0x20, 20, 30);
    let youngest = make_obj(0x30, 30, 30);
    let oldest_id = oldest.object_id;
    let mid_id = mid.object_id;
    let youngest_id = youngest.object_id;
    store.quarantine(oldest).expect("anchor quarantine oldest");
    store.quarantine(mid).expect("anchor quarantine mid");
    store
        .quarantine(youngest)
        .expect("anchor quarantine youngest");

    // 4th entry forces eviction.
    let intruder = make_obj(0x40, 40, 30);
    let intruder_id = intruder.object_id;
    store
        .quarantine(intruder)
        .expect("anchor quarantine intruder");

    // Oldest MUST be evicted first.
    assert!(
        !store.contains(&oldest_id),
        "ANCHOR REGRESSION: oldest entry (received_at=10) NOT evicted on \
         quota-forced eviction — EvictionEntry::cmp ordering broken; \
         attacker could keep stale entries pinned indefinitely"
    );
    // Mid + youngest + intruder MUST still be present.
    assert!(
        store.contains(&mid_id),
        "ANCHOR REGRESSION: mid evicted before oldest"
    );
    assert!(
        store.contains(&youngest_id),
        "ANCHOR REGRESSION: youngest evicted before oldest"
    );
    assert!(
        store.contains(&intruder_id),
        "ANCHOR: intruder (the very entry forcing eviction) is missing"
    );

    // (c) Idempotent quarantine.
    let store = QuarantineStore::new(small_policy());
    let obj = make_obj(0x55, 100, 64);
    let oid = obj.object_id;
    store
        .quarantine(obj.clone())
        .expect("anchor first quarantine");
    let used_after_first = store.zone_stats(&ZoneId::work()).used_bytes;
    store
        .quarantine(obj.clone())
        .expect("anchor second quarantine");
    let used_after_second = store.zone_stats(&ZoneId::work()).used_bytes;
    assert_eq!(
        used_after_first, used_after_second,
        "ANCHOR REGRESSION: idempotent quarantine inflated used_bytes \
         ({used_after_first} → {used_after_second}) — second quarantine \
         silently double-counted"
    );
    assert!(
        store.contains(&oid),
        "ANCHOR: object missing after idempotent re-quarantine"
    );
}
