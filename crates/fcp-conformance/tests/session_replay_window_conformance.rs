//! `fcp_protocol::session::ReplayWindow` per-frame sliding-bitmap
//! replay-protection conformance.
//!
//! `ReplayWindow` tracks accepted FCPS frame sequence numbers via a
//! 128-bit sliding bitmap. It fires BEFORE expensive MAC verification
//! so an attacker replaying captured frames cannot force the receiver
//! into a CPU-exhaustion loop. This is distinct from
//! `HelloReplayWindow` (session-handshake nonce, pinned in
//! session_nonce_replay_conformance.rs) — that one keys by
//! (`from_node`, `nonce`); this one keys by sequence number alone
//! within an already-authenticated session.
//!
//! Invariants pinned (NORMATIVE):
//!
//! 1. **seq=0 is the unset sentinel and MUST always be rejected.**
//!    Otherwise an attacker who never observed a real seq could
//!    inject seq=0 to slip past the gate.
//! 2. **Strictly-increasing seq is always accepted.**
//! 3. **Replay of an already-accepted seq is rejected on second
//!    presentation.**
//! 4. **Out-of-window seq (`highest - seq >= window_size`) is rejected.**
//! 5. **Out-of-order in-window seq is still accepted** (non-strict
//!    ordering — the bitmap remembers each seq independently).
//! 6. **`check()` is non-mutating** — must NOT consume bitmap state.
//!    Otherwise a probe-then-decide pattern would burn the seq slot
//!    on the probe.
//! 7. **`check_and_update()` mutates** — second call with same seq
//!    rejects.
//! 8. **Far-future seq slides the window** — older entries fall out.

use fcp_protocol::session::ReplayWindow;

#[test]
fn seq_zero_is_always_rejected() {
    // seq=0 is the unset sentinel. Otherwise an attacker could
    // inject a frame with seq=0 to bypass the replay gate.
    let mut window = ReplayWindow::new(64);
    assert!(
        !window.check(0),
        "check(0) MUST return false (seq=0 is the unset sentinel)"
    );
    assert!(
        !window.check_and_update(0),
        "check_and_update(0) MUST return false"
    );
}

#[test]
fn strictly_increasing_seq_is_always_accepted() {
    let mut window = ReplayWindow::new(64);
    for seq in 1..=200_u64 {
        assert!(
            window.check_and_update(seq),
            "monotonic seq {seq} must always be accepted"
        );
    }
    assert_eq!(window.highest_seq(), 200);
}

#[test]
fn replay_of_same_seq_is_rejected_on_second_presentation() {
    let mut window = ReplayWindow::new(64);
    assert!(window.check_and_update(10));
    assert!(
        !window.check_and_update(10),
        "second presentation of seq=10 MUST reject (replay defense)"
    );
}

#[test]
fn out_of_window_seq_is_rejected() {
    // window_size = 8. Advance to seq=100, then try to accept
    // seq=50 (delta = 50, far past the window). Must reject.
    let mut window = ReplayWindow::new(8);
    assert!(window.check_and_update(100));

    assert!(
        !window.check_and_update(50),
        "seq=50 is 50 steps below highest=100; window_size=8 means it MUST be rejected"
    );
    assert!(
        !window.check(50),
        "check(50) must agree with check_and_update on out-of-window rejection"
    );
}

#[test]
fn out_of_order_in_window_seq_is_still_accepted() {
    // The window MUST handle re-ordered delivery: seq=10 then seq=8
    // both accepted because seq=8 is within the window of
    // [highest-window_size+1 .. highest] inclusive.
    let mut window = ReplayWindow::new(8);
    assert!(window.check_and_update(10));
    assert!(
        window.check_and_update(8),
        "in-window out-of-order seq=8 (when highest=10, window_size=8) MUST be accepted"
    );
    // But re-presenting seq=8 must reject.
    assert!(
        !window.check_and_update(8),
        "second presentation of seq=8 still rejects (the bitmap remembers)"
    );
}

#[test]
fn check_is_non_mutating() {
    // Critical: a probe call to check() MUST NOT consume the seq
    // slot. Otherwise a "probe then decide" caller pattern would
    // accept a seq via check() but reject on subsequent
    // check_and_update().
    let mut window = ReplayWindow::new(64);
    window.check_and_update(5); // establish baseline

    // Probe seq=10 several times via check() — this must NOT mutate.
    for _ in 0..10 {
        assert!(
            window.check(10),
            "check(10) on a fresh seq must always return true"
        );
    }

    // After all those probes, check_and_update(10) MUST still accept.
    assert!(
        window.check_and_update(10),
        "check() probes did not mutate; check_and_update(10) must still succeed"
    );

    // And the SECOND check_and_update(10) MUST reject (this is the
    // mutating one).
    assert!(
        !window.check_and_update(10),
        "second check_and_update(10) rejects after the prior accept"
    );
}

#[test]
fn far_future_seq_slides_the_window_and_evicts_older_entries() {
    // window_size = 8. Accept seq=5. Then jump to seq=200. The
    // window has slid past seq=5; presenting seq=5 again must
    // reject (out of window now).
    let mut window = ReplayWindow::new(8);
    assert!(window.check_and_update(5));
    assert!(window.check_and_update(200));
    assert!(
        !window.check_and_update(5),
        "seq=5 is now far below the slid window (highest=200, window_size=8); MUST reject"
    );
}

#[test]
fn bitmap_caps_at_128_entries_regardless_of_window_size() {
    // The bitmap is u128; window_size larger than 128 is still
    // capped by the bitmap width. Pin that in-window-but-beyond-128
    // is rejected.
    let mut window = ReplayWindow::new(256);
    assert!(window.check_and_update(200));
    // seq = 200 - 128 = 72: delta = 128, which the implementation
    // rejects (`diff >= 128`).
    assert!(
        !window.check_and_update(72),
        "seq with delta>=128 from highest MUST reject regardless of configured window_size"
    );
    // delta=127 should still be accepted.
    assert!(
        window.check_and_update(73),
        "seq with delta=127 (within bitmap width) must be accepted"
    );
}

#[test]
fn highest_seq_advances_only_on_acceptance() {
    let mut window = ReplayWindow::new(8);
    assert_eq!(window.highest_seq(), 0, "fresh window starts at 0");

    assert!(window.check_and_update(50));
    assert_eq!(window.highest_seq(), 50);

    // An out-of-order in-window accept MUST NOT advance highest_seq.
    assert!(window.check_and_update(48));
    assert_eq!(
        window.highest_seq(),
        50,
        "out-of-order accept must NOT advance highest_seq"
    );

    // A rejected replay MUST NOT advance highest_seq.
    assert!(!window.check_and_update(48));
    assert_eq!(window.highest_seq(), 50);

    // A new high seq advances.
    assert!(window.check_and_update(60));
    assert_eq!(window.highest_seq(), 60);
}

#[test]
fn window_size_zero_is_clamped_to_at_least_one() {
    // ReplayWindow::new(0) might trivially accept everything if not
    // clamped. The implementation clamps to max(1, window_size).
    // Pin that the clamp behaves so a misconfigured zero still
    // rejects out-of-window replay.
    let mut window = ReplayWindow::new(0);
    assert!(window.check_and_update(10));
    // After accepting seq=10, replaying seq=10 must reject.
    assert!(
        !window.check_and_update(10),
        "even with window_size=0 (clamped to 1), an exact replay must reject"
    );
}
