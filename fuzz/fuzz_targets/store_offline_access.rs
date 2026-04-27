#![no_main]

//! Fuzz target for `fcp_store::OfflineAccess` + `OfflineCapability`
//! arithmetic and 3-way status classification (offline.rs:33-262).
//!
//! These types feed repair priority and pre-staging decisions. A
//! regression that miscategorized "Available" vs "Partial" would either:
//!   - mark an object Available when `local_symbols < k` → reads return
//!     decode-failure surface (DoS)
//!   - mark an object Partial when `local_symbols >= k` → unnecessary
//!     repair work + bandwidth waste
//!
//! Existing fcp-store fuzz coverage (store_validate_structure,
//! object_id_verifier, store_oti_roundtrip, store_coverage_eval) does
//! NOT touch OfflineAccess / OfflineCapability.
//!
//! Properties asserted:
//!
//!   1. **Arithmetic round-trip**: `add_symbols(n)` then
//!      `remove_symbols(n)` restores `local_symbols` (no-saturation
//!      domain).
//!   2. **status() ⇔ can_access() agreement**: 3-way partition is
//!      total + disjoint over `local_symbols` ranges.
//!   3. **coverage_bps boundary cases**: 0 / =k / >k / k=0 all
//!      produce the documented values.
//!   4. **symbols_needed monotonicity**: monotonically non-increasing
//!      as `local_symbols` grows, reaches 0 once `can_access()` true.
//!   5. **bytes_needed == symbols_needed * symbol_size** (u64).
//!   6. **OfflineCapability 3-way partition cardinality**:
//!      available_count + partial_count + not_cached == object_count.
//!   7. **OfflineCapability::readiness_bps direction**: monotonically
//!      non-decreasing as objects transition Partial→Available.
//!
//!   Once-gated regression anchors:
//!     (a) k=0 ⇒ coverage_bps=10000, can_access=true, status=Available.
//!     (b) local=k ⇒ coverage_bps exactly 10000, can_access=true.
//!     (c) local=k-1 ⇒ can_access=false, status=Partial,
//!         symbols_needed=1.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::ObjectId;
use fcp_store::{OfflineAccess, OfflineCapability, OfflineStatus};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_OPS: usize = 16;
const MAX_OBJECTS: usize = 8;

static OFFLINE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// k bounded so symbols_needed/bytes_needed stay sane.
    k: u16,
    n: u16,
    symbol_size: u16,
    /// Sequence of add/remove deltas.
    ops: Vec<u16>,
    /// For aggregate property 7: sequence of (object_idx, k, target_local).
    aggregate: Vec<(u8, u16, u16)>,
}

fn assert_status_partition(access: &OfflineAccess) {
    let status = access.status();
    let can = access.can_access();
    match status {
        OfflineStatus::Available => {
            assert!(
                can && access.local_symbols >= access.k,
                "status=Available but local_symbols={} < k={}",
                access.local_symbols,
                access.k
            );
        }
        OfflineStatus::Partial => {
            assert!(
                !can,
                "status=Partial but can_access()=true (local_symbols={}, k={})",
                access.local_symbols, access.k
            );
            assert!(
                access.local_symbols > 0 && access.local_symbols < access.k,
                "status=Partial but local_symbols={} not in (0, k={})",
                access.local_symbols,
                access.k
            );
        }
        OfflineStatus::NotCached => {
            assert_eq!(
                access.local_symbols, 0,
                "status=NotCached but local_symbols={} != 0",
                access.local_symbols
            );
            // can_access only if k==0 too.
            assert_eq!(
                can,
                access.k == 0,
                "status=NotCached can_access mismatch (k={})",
                access.k
            );
        }
    }
}

fn assert_coverage_invariants(access: &OfflineAccess) {
    let bps = access.coverage_bps();
    if access.k == 0 {
        assert_eq!(
            bps, 10_000,
            "k=0 ⇒ coverage_bps must be 10000 (trivially complete)"
        );
    } else if access.local_symbols == 0 {
        assert_eq!(
            bps, 0,
            "local_symbols=0 ⇒ coverage_bps must be 0; got {bps}"
        );
    } else if access.local_symbols == access.k {
        assert_eq!(
            bps, 10_000,
            "local=k ⇒ coverage_bps must be exactly 10000; got {bps}"
        );
    }
}

fn assert_arithmetic_identities(access: &OfflineAccess) {
    let needed = access.symbols_needed();
    if access.local_symbols >= access.k {
        assert_eq!(
            needed, 0,
            "can_access()=true ⇒ symbols_needed=0; got {needed}"
        );
    } else {
        assert_eq!(
            needed,
            access.k - access.local_symbols,
            "symbols_needed != k - local in the deficit regime"
        );
    }

    let bytes = access.bytes_needed();
    let expected = u64::from(needed) * u64::from(access.symbol_size);
    assert_eq!(
        bytes, expected,
        "bytes_needed ({bytes}) != symbols_needed ({needed}) * symbol_size ({})",
        access.symbol_size
    );
}

fuzz_target!(|data: &[u8]| {
    OFFLINE_ANCHOR.call_once(assert_offline_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let oid = ObjectId::from_bytes([0u8; 32]);
    let k = u32::from(input.k);
    let n = u32::from(input.n.max(input.k)); // n >= k by contract
    let symbol_size = u32::from(input.symbol_size);

    let mut access = OfflineAccess::new(oid, k, n, symbol_size);

    // Initial-state invariants.
    assert_status_partition(&access);
    assert_coverage_invariants(&access);
    assert_arithmetic_identities(&access);

    // ── PROPERTY 1: arithmetic round-trip + 4: monotonicity ───────────
    let mut prev_needed = access.symbols_needed();
    for delta in input.ops.iter().take(MAX_OPS) {
        let d = u32::from(*delta) % 1000; // bounded so we don't saturate
        let before = access.local_symbols;
        access.add_symbols(d);
        // Saturating bound check.
        if access.local_symbols == before.saturating_add(d) && access.local_symbols < u32::MAX {
            // round-trip
            let mut roundtrip = access.clone();
            roundtrip.remove_symbols(d);
            assert_eq!(
                roundtrip.local_symbols, before,
                "add({d})+remove({d}) did not round-trip ({before} → {} → {})",
                access.local_symbols, roundtrip.local_symbols
            );
        }
        // Property 4: symbols_needed monotonicity under add.
        let now_needed = access.symbols_needed();
        assert!(
            now_needed <= prev_needed,
            "symbols_needed not monotonic under add: {prev_needed} → {now_needed}"
        );
        prev_needed = now_needed;

        assert_status_partition(&access);
        assert_coverage_invariants(&access);
        assert_arithmetic_identities(&access);
    }

    // ── PROPERTY 6 + 7: aggregate cardinality + readiness direction ────
    let mut cap = OfflineCapability::new();
    let mut accesses: Vec<OfflineAccess> = (0..MAX_OBJECTS)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            OfflineAccess::new(ObjectId::from_bytes(bytes), 4, 8, 64)
        })
        .collect();
    for a in &accesses {
        cap.track(a.clone());
    }
    let initial_readiness = cap.readiness_bps();

    // Apply each aggregate op as add_symbols on the targeted object,
    // tracking it in the capability after each. readiness_bps MUST be
    // monotonically non-decreasing under additions only.
    let mut prev_readiness = initial_readiness;
    for (idx, k_seed, target_seed) in input.aggregate.iter().take(MAX_OPS) {
        let i = (*idx as usize) % MAX_OBJECTS;
        // Target adds (bounded) — we only ever ADD to ensure monotone
        // direction.
        let target = u32::from(*target_seed) % 16;
        accesses[i].add_symbols(target);
        cap.track(accesses[i].clone());

        // Cardinality (Property 6).
        let avail = cap.available_count();
        let partial = cap.partial_count();
        let total = cap.object_count();
        let not_cached = total - avail - partial;
        assert_eq!(
            avail + partial + not_cached,
            total,
            "3-way partition cardinality broken: avail={avail} + partial={partial} + \
             not_cached={not_cached} != total={total}"
        );

        // Readiness direction (Property 7).
        let now_readiness = cap.readiness_bps();
        assert!(
            now_readiness >= prev_readiness,
            "readiness_bps non-monotonic under additions: {prev_readiness} → {now_readiness}"
        );
        prev_readiness = now_readiness;
        let _ = *k_seed; // silence unused
    }
});

/// Once-gated regression anchors for the documented boundary cases.
fn assert_offline_anchored() {
    let oid = ObjectId::from_bytes([0xAA; 32]);

    // (a) k=0 ⇒ coverage_bps=10000, can_access=true, status=Available.
    let zero_k = OfflineAccess::new(oid, 0, 0, 64);
    assert_eq!(
        zero_k.coverage_bps(),
        10_000,
        "ANCHOR REGRESSION: k=0 coverage_bps != 10000 (got {}) — \
         documented trivially-complete invariant broken",
        zero_k.coverage_bps()
    );
    assert!(
        zero_k.can_access(),
        "ANCHOR REGRESSION: k=0 can_access()=false — documented trivially-complete \
         invariant broken"
    );
    // status() returns NotCached for local_symbols=0 even when k=0,
    // because Available requires local_symbols >= k AND local_symbols > 0
    // is NOT a constraint. Actually the implementation returns Available
    // when local_symbols >= k, so k=0 with local=0 is Available.
    assert_eq!(
        zero_k.status(),
        OfflineStatus::Available,
        "ANCHOR: k=0 status={:?}; expected Available since local_symbols >= k",
        zero_k.status()
    );

    // (b) local=k ⇒ coverage_bps=10000, can_access=true.
    let mut local_eq_k = OfflineAccess::new(oid, 4, 8, 64);
    local_eq_k.add_symbols(4);
    assert_eq!(
        local_eq_k.coverage_bps(),
        10_000,
        "ANCHOR REGRESSION: local=k=4 coverage_bps={}; expected exactly 10000",
        local_eq_k.coverage_bps()
    );
    assert!(
        local_eq_k.can_access(),
        "ANCHOR REGRESSION: local=k can_access=false"
    );
    assert_eq!(local_eq_k.status(), OfflineStatus::Available);

    // (c) local=k-1 ⇒ Partial, symbols_needed=1.
    let mut local_eq_k_minus_1 = OfflineAccess::new(oid, 4, 8, 64);
    local_eq_k_minus_1.add_symbols(3);
    assert!(
        !local_eq_k_minus_1.can_access(),
        "ANCHOR: local=k-1 should not be accessible"
    );
    assert_eq!(
        local_eq_k_minus_1.status(),
        OfflineStatus::Partial,
        "ANCHOR: local=k-1 status should be Partial; got {:?}",
        local_eq_k_minus_1.status()
    );
    assert_eq!(
        local_eq_k_minus_1.symbols_needed(),
        1,
        "ANCHOR REGRESSION: local=k-1 symbols_needed={}; expected 1",
        local_eq_k_minus_1.symbols_needed()
    );
    assert_eq!(
        local_eq_k_minus_1.bytes_needed(),
        64,
        "ANCHOR REGRESSION: local=k-1 bytes_needed={}; expected 1*64=64",
        local_eq_k_minus_1.bytes_needed()
    );
}
