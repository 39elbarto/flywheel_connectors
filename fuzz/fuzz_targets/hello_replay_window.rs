#![no_main]

//! State-machine fuzz target for `HelloReplayWindow` (session.rs:553-599).
//!
//! The replay window is the bounded-FIFO duplicate-rejection gate that
//! `verify_hello_attested_with_replay` (session.rs:650-662) consults to
//! reject re-played hellos still inside the active window. A regression
//! in its bookkeeping would either:
//!   - admit a duplicate (from, nonce) within the active window →
//!     handshake-replay attack surface re-opened
//!   - cap-bypass (seen.len() > capacity) → DoS amplification surface
//!     for attackers spraying distinct (from, nonce) tuples
//!   - evict-too-aggressively → re-admit a still-fresh hello (also
//!     replay-class, narrower attacker, narrower window).
//!
//! Existing fcp-protocol fuzz coverage in this area
//! (session_metamorphic, session_cookie_binding, derive_session_keys,
//! session_transcript, session) does NOT exercise HelloReplayWindow.
//!
//! Properties asserted:
//!
//!   1. **First-time accept**: a hello not in the window MUST be
//!      accepted by check_and_update.
//!   2. **Immediate-replay reject**: re-inserting the SAME hello MUST
//!      be rejected; check returns false in lockstep.
//!   3. **check ⇔ check_and_update agreement on rejection**: if
//!      check(h) returns false, check_and_update(h) MUST also return
//!      false on the next call (and not mutate state).
//!   4. **(from, nonce) keying**: two hellos differing in `from` MUST
//!      be tracked independently; two hellos differing in `nonce` only
//!      MUST also be tracked independently.
//!
//!   Once-gated regression anchors:
//!     (a) Capacity-boundary FIFO: after `capacity + 1` unique inserts
//!         the OLDEST key MUST have been evicted; re-inserting it MUST
//!         be accepted again.
//!     (b) `(from, nonce)` keying: hellos with same nonce but different
//!         from MUST both be admitted; hellos with same from but
//!         different nonce MUST both be admitted.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::TailscaleNodeId;
use fcp_crypto::X25519PublicKey;
use fcp_protocol::{HelloReplayWindow, MeshSessionHello, SessionNonce};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const NONCE_SIZE: usize = 16;
const MAX_OPS: usize = 32;
const CAPACITY_RANGE: usize = 8;
/// Pool of `from` ids — fold the fuzzer's `from_disc` modulo this so
/// we exercise the keying MR with a small, deterministic set.
const FROM_POOL_SIZE: u8 = 4;

static REPLAY_WINDOW_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug, Clone, Copy)]
struct OpSeed {
    from_disc: u8,
    nonce: [u8; NONCE_SIZE],
}

#[derive(Arbitrary, Debug)]
struct Input {
    capacity_seed: u8,
    ops: Vec<OpSeed>,
}

fn from_for(disc: u8) -> TailscaleNodeId {
    let idx = disc % FROM_POOL_SIZE;
    TailscaleNodeId::new(format!("node-{idx}"))
}

fn make_hello(from_disc: u8, nonce_bytes: [u8; NONCE_SIZE]) -> MeshSessionHello {
    // Static dummy eph key — only (from, nonce) participates in the
    // replay key, so the rest can be zeroed.
    let eph = X25519PublicKey::from_bytes([0u8; 32]);

    MeshSessionHello {
        from: from_for(from_disc),
        to: TailscaleNodeId::new("node-responder"),
        eph_pubkey: eph,
        nonce: SessionNonce(nonce_bytes),
        cookie: None,
        timestamp: 0,
        suites: vec![],
        transport_limits: None,
        signature: None,
    }
}

fuzz_target!(|data: &[u8]| {
    REPLAY_WINDOW_ANCHOR.call_once(assert_replay_window_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let capacity = ((input.capacity_seed as usize) % CAPACITY_RANGE) + 1;
    let mut window = HelloReplayWindow::new(capacity);

    // Track the (from_disc, nonce) tuples we expect to be in the window
    // so we can validate check / check_and_update outcomes against the
    // FIFO model. We model the window externally as a VecDeque.
    let mut model: std::collections::VecDeque<(u8, [u8; NONCE_SIZE])> =
        std::collections::VecDeque::with_capacity(capacity);

    for op in input.ops.iter().take(MAX_OPS) {
        let key = (op.from_disc % FROM_POOL_SIZE, op.nonce);
        let hello = make_hello(op.from_disc, op.nonce);

        // ── PROPERTY 3: check ⇔ check_and_update agreement on rejection ─
        // If check returns false, check_and_update MUST also return false.
        let check_result = window.check(&hello);
        let in_model = model.iter().any(|m| m == &key);
        // The model says "in window" iff the key is present.
        assert_eq!(
            !check_result, in_model,
            "check returned {check_result}, but model says in_window={in_model} \
             for key={key:?}"
        );

        let cau_result = window.check_and_update(&hello);
        if !check_result {
            assert!(
                !cau_result,
                "check returned false but check_and_update returned true — \
                 agreement broken; replay surface re-opened"
            );
            // model unchanged — duplicate rejected.
        } else {
            // ── PROPERTY 1: first-time accept ─────────────────────────
            assert!(
                cau_result,
                "check returned true (first-time) but check_and_update \
                 rejected — agreement broken in the other direction"
            );
            // Update model: insert at back, evict from front if over capacity.
            model.push_back(key);
            while model.len() > capacity {
                model.pop_front();
            }
        }

        // ── PROPERTY 2: immediate-replay reject ───────────────────────
        // Re-inserting the same hello immediately MUST be rejected.
        let immediate_replay = window.check_and_update(&hello);
        assert!(
            !immediate_replay,
            "immediate-replay of just-inserted hello (key={key:?}) was \
             accepted — duplicate-rejection broken"
        );
    }
});

/// Once-gated regression anchors for the most load-bearing replay
/// invariants.
fn assert_replay_window_anchored() {
    // (a) Capacity-boundary FIFO eviction with re-admit.
    let capacity = 3;
    let mut window = HelloReplayWindow::new(capacity);
    let h0 = make_hello(0, [0x00; NONCE_SIZE]);
    let h1 = make_hello(0, [0x01; NONCE_SIZE]);
    let h2 = make_hello(0, [0x02; NONCE_SIZE]);
    let h3 = make_hello(0, [0x03; NONCE_SIZE]); // pushes h0 out

    assert!(window.check_and_update(&h0), "ANCHOR: h0 first-insert");
    assert!(window.check_and_update(&h1), "ANCHOR: h1 first-insert");
    assert!(window.check_and_update(&h2), "ANCHOR: h2 first-insert");
    assert!(
        window.check_and_update(&h3),
        "ANCHOR: h3 first-insert (capacity+1 unique)"
    );

    // h0 must now be evicted — re-inserting it should succeed.
    assert!(
        window.check_and_update(&h0),
        "ANCHOR REGRESSION: h0 was NOT evicted after capacity+1 unique inserts \
         — FIFO eviction at session.rs:592-596 broken; window is leaking older \
         entries past capacity (memory amplification + missed eviction)."
    );

    // h1, h2, h3 should all still be present (immediate replays MUST reject).
    assert!(
        !window.check_and_update(&h1),
        "ANCHOR REGRESSION: h1 was incorrectly evicted before h0 — FIFO order broken"
    );
    assert!(
        !window.check_and_update(&h2),
        "ANCHOR REGRESSION: h2 was incorrectly evicted — FIFO order broken"
    );
    assert!(
        !window.check_and_update(&h3),
        "ANCHOR REGRESSION: h3 was incorrectly evicted — FIFO order broken"
    );

    // (b) (from, nonce) keying — same nonce, different from.
    let mut window = HelloReplayWindow::new(8);
    let same_nonce = [0xAB; NONCE_SIZE];
    let from_a = make_hello(0, same_nonce);
    let from_b = make_hello(1, same_nonce);
    assert!(
        window.check_and_update(&from_a),
        "ANCHOR: from_a/same_nonce first-insert"
    );
    assert!(
        window.check_and_update(&from_b),
        "ANCHOR REGRESSION: from_b/same_nonce was rejected — replay key keyed \
         only on nonce (from dropped) — peer A could lock peer B out of new \
         sessions by pre-claiming a nonce."
    );

    // Same from, different nonce.
    let mut window = HelloReplayWindow::new(8);
    let same_from = 2;
    let nonce_x = make_hello(same_from, [0x00; NONCE_SIZE]);
    let nonce_y = make_hello(same_from, [0xFF; NONCE_SIZE]);
    assert!(
        window.check_and_update(&nonce_x),
        "ANCHOR: same_from/nonce_x"
    );
    assert!(
        window.check_and_update(&nonce_y),
        "ANCHOR REGRESSION: same_from/nonce_y was rejected — replay key keyed \
         only on from (nonce dropped) — every legitimate fresh hello from a \
         peer would be rejected after the first."
    );
}
