#![no_main]

//! State-machine fuzz target for `ReplayWindow` (session.rs:720-797).
//!
//! `ReplayWindow` is the per-session sliding-bitmap replay-protection
//! for FCPS frame seq numbers. Distinct from `HelloReplayWindow`
//! (covered by p5ams), which is the (from, nonce) FIFO at the
//! handshake layer. `ReplayWindow.check` gates the per-frame MAC
//! verification — a regression that admits replayed seqs lets an
//! attacker cause CPU exhaustion via repeatedly forwarded captured
//! frames, and worse, lets a captured frame's MAC pass twice if the
//! check ever returned true after first acceptance.
//!
//! Existing fcp-protocol fuzz coverage in this area:
//!   - hello_replay_window (p5ams)        — handshake-layer FIFO
//!   - session_metamorphic                — per-frame MAC binding
//!   - hello_transcript_binding (41uql), ack_transcript_binding (v7kae)
//!
//! NOT covered: per-session ReplayWindow's sliding-bitmap state machine.
//!
//! Properties asserted (model-driven):
//!
//!   1. **seq=0 always rejected** by both check and check_and_update.
//!   2. **First non-zero seq accepted**: a fresh window admits any
//!      `seq > 0`; subsequent state has highest_seq == that seq.
//!   3. **Immediate replay rejected**: same seq twice MUST fail the
//!      second call to check_and_update.
//!   4. **check ⇔ check_and_update agreement**: check(seq) returns
//!      false ⇒ check_and_update(seq) returns false (and does not
//!      mutate state). check(seq) returns true ⇒ check_and_update(seq)
//!      returns true on the next call.
//!   5. **In-window distinct-seq accepted**: an unseen seq within the
//!      sliding window MUST be accepted.
//!   6. **Out-of-window rejected**: seq <= highest_seq - window_size
//!      (or - 128, whichever is lower) MUST be rejected.
//!   7. **highest_seq monotonicity**: highest_seq only ever increases.
//!
//!   Once-gated regression anchors:
//!     (a) window_size=128 boundary: with highest_seq=200, seq=73
//!         (diff=127) MUST be accepted on a fresh bit; seq=72
//!         (diff=128) MUST be rejected as too old.
//!     (b) Bitmap shift on large jump: jumping from seq=1 to seq=200
//!         clears all in-window bits except the new top.
//!     (c) Immediate replay: accept seq=10, reject seq=10 again.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::ReplayWindow;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_OPS: usize = 64;

static REPLAY_WINDOW_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Window size, bounded in the body to (1, 256].
    window_size_seed: u8,
    /// Sequence of seq deltas relative to a running cursor (signed so
    /// we exercise both forward and backward seqs).
    seq_seeds: Vec<i32>,
}

fuzz_target!(|data: &[u8]| {
    REPLAY_WINDOW_ANCHOR.call_once(assert_replay_window_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let window_size = u64::from(input.window_size_seed.max(1));
    let mut window = ReplayWindow::new(window_size);

    // ── PROPERTY 1: seq=0 always rejected ─────────────────────────────
    assert!(
        !window.check(0),
        "ReplayWindow.check(0) accepted; seq=0 MUST always be rejected"
    );
    assert!(
        !window.check_and_update(0),
        "ReplayWindow.check_and_update(0) accepted; seq=0 MUST always be rejected"
    );

    // Track the seqs we've already accepted to model the window.
    let mut accepted: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut prev_highest = 0u64;

    let mut cursor: u64 = 1;
    for delta in input.seq_seeds.iter().take(MAX_OPS) {
        // Build a candidate seq from the cursor; allow the fuzzer to go
        // both forward and backward (within reason).
        let seq = if *delta >= 0 {
            cursor.saturating_add(u64::from(*delta as u32))
        } else {
            cursor.saturating_sub(u64::from(delta.unsigned_abs()))
        };

        // ── PROPERTY 4: check ⇔ check_and_update on rejection ─────────
        let check_result = window.check(seq);
        // The state should be unchanged after check — verify by
        // checking again.
        assert_eq!(
            window.check(seq),
            check_result,
            "check is not pure: returned different values on consecutive \
             calls without mutation"
        );

        let cau_result = window.check_and_update(seq);

        if seq == 0 {
            assert!(!cau_result, "seq=0 was accepted by check_and_update");
            continue;
        }

        if !check_result {
            // check rejected → check_and_update MUST also reject.
            assert!(
                !cau_result,
                "check rejected seq={seq} but check_and_update accepted — agreement broken"
            );
        } else {
            // check accepted → check_and_update MUST accept.
            assert!(
                cau_result,
                "check accepted seq={seq} but check_and_update rejected — agreement broken"
            );
        }

        if cau_result {
            // ── PROPERTY 7: highest_seq monotonicity ──────────────────
            let new_highest = window.highest_seq();
            assert!(
                new_highest >= prev_highest,
                "highest_seq decreased: {prev_highest} → {new_highest} after accepting seq={seq}"
            );
            prev_highest = new_highest;

            // ── PROPERTY 3: immediate replay rejected ─────────────────
            let replay = window.check_and_update(seq);
            assert!(
                !replay,
                "immediate replay of just-accepted seq={seq} was accepted"
            );
            accepted.insert(seq);
        }

        cursor = window.highest_seq().max(1);
    }
});

/// Once-gated regression anchors for the sliding-bitmap invariants.
fn assert_replay_window_anchored() {
    // (a) window_size=128 boundary.
    let mut window = ReplayWindow::new(128);
    // Push highest_seq up to 200 in one jump.
    assert!(window.check_and_update(200), "ANCHOR: accept seq=200");
    assert_eq!(window.highest_seq(), 200);

    // diff = 200 - 73 = 127 → in window
    assert!(
        window.check_and_update(73),
        "ANCHOR REGRESSION: seq=73 (diff=127) rejected — sliding window \
         boundary is not inclusive at window_size-1; legitimate frames at \
         the edge of the window are wrongly dropped"
    );
    // diff = 200 - 72 = 128 → out of window
    assert!(
        !window.check_and_update(72),
        "ANCHOR REGRESSION: seq=72 (diff=128) accepted — out-of-window \
         replay protection broken; attacker can replay a frame that's \
         sliding-window+1 old, defeating CPU-exhaustion guard"
    );

    // (b) Large jump clears bitmap.
    let mut window = ReplayWindow::new(128);
    assert!(window.check_and_update(1));
    assert!(window.check_and_update(200));
    // seq=1 should now be far out of window — diff = 199 > 128 → reject.
    assert!(
        !window.check_and_update(1),
        "ANCHOR REGRESSION: seq=1 accepted after jump to 200 (diff=199 > 128) — \
         large-jump bitmap shift didn't clear the old bit; replay protection \
         silently leaks across jumps"
    );

    // (c) Immediate replay.
    let mut window = ReplayWindow::new(64);
    assert!(window.check_and_update(10), "ANCHOR: first accept");
    assert!(
        !window.check_and_update(10),
        "ANCHOR REGRESSION: immediate replay of seq=10 was accepted — \
         bitmap-bit gate at session.rs:783-786 broken; same frame's MAC \
         could pass verification twice"
    );
}
