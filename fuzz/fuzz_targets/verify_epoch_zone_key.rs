#![no_main]

//! Fuzz target for `fcp_core::pcs::verify_epoch_zone_key`
//! (pcs.rs:572) and `PcsGroupState::derive_zone_key_for_epoch`
//! (pcs.rs:230).
//!
//! These are the PCS forward-secrecy verification primitives used to
//! confirm that a zone key was derived from a specific epoch secret.
//! NOT covered as a discrete unit by any existing fuzz target —
//! `pcs_group_state` exercises the group state machine but never the
//! `verify_epoch_zone_key` standalone path.
//!
//! A regression that:
//!   - made verification ignore the epoch counter would let a stale
//!     key from epoch N pass verification at epoch N+1 (defeating
//!     forward secrecy at the verification layer).
//!   - dropped zone-id binding would allow a key derived for zone A
//!     to verify against zone B with the same secret.
//!   - flipped the result polarity would silently turn a verifier
//!     into an attacker oracle.
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: `verify_epoch_zone_key(zone, secret, epoch,
//!      &derive_zone_key_for_epoch(zone, secret, epoch))` returns
//!      `Ok(true)`.
//!   2. **Determinism**: `derive_zone_key_for_epoch` is pure —
//!      repeated calls with the same input return the same key.
//!   3. **Wrong-secret rejection**: 1-bit flip on `epoch_secret` →
//!      `Ok(false)`.
//!   4. **Wrong-epoch rejection**: a different epoch → `Ok(false)`.
//!   5. **Wrong-zone rejection**: a different zone → `Ok(false)`.
//!   6. **Wrong-key rejection**: 1-bit-flipped expected key →
//!      `Ok(false)`.
//!   7. **Cross-zone keys distinct**: derive for two different
//!      `ZoneId` produces distinct keys at the same secret + epoch.
//!
//!   Once-gated anchors verify each rejection branch on hand-picked
//!   inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::pcs::{PcsGroupState, verify_epoch_zone_key};
use fcp_core::{ZoneId, ZoneKey};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static EPOCH_ZK_ANCHOR: Once = Once::new();

const ZONES: [&str; 5] = ["z:owner", "z:private", "z:work", "z:community", "z:public"];

#[derive(Arbitrary, Debug)]
struct Input {
    zone_disc: u8,
    other_zone_disc: u8,
    epoch_secret: [u8; 32],
    epoch: u64,
    /// Byte to flip in the secret for Property 3 (mod 32).
    secret_flip: u8,
    /// Byte to flip in the expected key for Property 6 (mod 32).
    key_flip: u8,
    /// Delta to apply to epoch for Property 4 (XORed in to ensure non-zero).
    epoch_delta: u64,
}

fn pick_zone(disc: u8) -> ZoneId {
    let z = ZONES[(disc as usize) % ZONES.len()];
    ZoneId::try_from(z.to_string()).expect("ZONES contains valid canonical ids")
}

fuzz_target!(|data: &[u8]| {
    EPOCH_ZK_ANCHOR.call_once(assert_epoch_zk_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let zone = pick_zone(input.zone_disc);
    let other_zone = pick_zone(input.other_zone_disc);

    // ── PROPERTY 2: determinism ─────────────────────────────────────────
    let key_a = PcsGroupState::derive_zone_key_for_epoch(&zone, &input.epoch_secret, input.epoch)
        .expect("derive_zone_key_for_epoch A");
    let key_b = PcsGroupState::derive_zone_key_for_epoch(&zone, &input.epoch_secret, input.epoch)
        .expect("derive_zone_key_for_epoch B");
    assert_eq!(
        key_a.as_bytes(),
        key_b.as_bytes(),
        "derive_zone_key_for_epoch non-deterministic"
    );

    // ── PROPERTY 1: round-trip ──────────────────────────────────────────
    match verify_epoch_zone_key(&zone, &input.epoch_secret, input.epoch, &key_a) {
        Ok(true) => {}
        other => panic!(
            "verify_epoch_zone_key on a freshly derived key returned {other:?}; expected Ok(true)"
        ),
    }

    // ── PROPERTY 3: wrong-secret rejection ──────────────────────────────
    let mut bad_secret = input.epoch_secret;
    let idx = (input.secret_flip as usize) % 32;
    bad_secret[idx] ^= 0x01;
    match verify_epoch_zone_key(&zone, &bad_secret, input.epoch, &key_a) {
        Ok(false) => {}
        other => panic!(
            "verify_epoch_zone_key with bit-flipped secret returned {other:?}; expected Ok(false)"
        ),
    }

    // ── PROPERTY 4: wrong-epoch rejection ───────────────────────────────
    // Construct a definitely-different epoch.
    let other_epoch = input.epoch.wrapping_add(input.epoch_delta.max(1));
    if other_epoch != input.epoch {
        match verify_epoch_zone_key(&zone, &input.epoch_secret, other_epoch, &key_a) {
            Ok(false) => {}
            other => panic!(
                "verify_epoch_zone_key with wrong epoch returned {other:?}; expected Ok(false)"
            ),
        }
    }

    // ── PROPERTY 5 + 7: wrong-zone rejection / cross-zone keys distinct ─
    if other_zone.as_str() != zone.as_str() {
        match verify_epoch_zone_key(&other_zone, &input.epoch_secret, input.epoch, &key_a) {
            Ok(false) => {}
            other => panic!(
                "verify_epoch_zone_key with wrong zone returned {other:?}; expected Ok(false)"
            ),
        }
        let cross_key =
            PcsGroupState::derive_zone_key_for_epoch(&other_zone, &input.epoch_secret, input.epoch)
                .expect("derive cross-zone");
        assert_ne!(
            key_a.as_bytes(),
            cross_key.as_bytes(),
            "cross-zone keys identical for same (secret, epoch) — zone binding lost"
        );
    }

    // ── PROPERTY 6: wrong-key rejection ─────────────────────────────────
    let mut bad_key_bytes = *key_a.as_bytes();
    let idx = (input.key_flip as usize) % 32;
    bad_key_bytes[idx] ^= 0x01;
    let bad_key = ZoneKey::from_bytes(bad_key_bytes);
    match verify_epoch_zone_key(&zone, &input.epoch_secret, input.epoch, &bad_key) {
        Ok(false) => {}
        other => panic!(
            "verify_epoch_zone_key on bit-flipped expected_key returned {other:?}; expected Ok(false)"
        ),
    }
});

/// Once-gated anchors: each rejection branch on hand-picked inputs.
fn assert_epoch_zk_anchored() {
    let zone = ZoneId::work();
    let other_zone = ZoneId::private();
    let secret = [0x42u8; 32];
    let epoch: u64 = 7;

    let key = PcsGroupState::derive_zone_key_for_epoch(&zone, &secret, epoch)
        .expect("ANCHOR: derive on known input");

    // (a) Round-trip on the anchor input.
    match verify_epoch_zone_key(&zone, &secret, epoch, &key) {
        Ok(true) => {}
        other => panic!(
            "ANCHOR REGRESSION: verify_epoch_zone_key on a freshly derived key returned {other:?}"
        ),
    }

    // (b) Wrong epoch.
    match verify_epoch_zone_key(&zone, &secret, epoch + 1, &key) {
        Ok(false) => {}
        other => panic!("ANCHOR REGRESSION: wrong-epoch verify returned {other:?}"),
    }

    // (c) Wrong zone.
    match verify_epoch_zone_key(&other_zone, &secret, epoch, &key) {
        Ok(false) => {}
        other => panic!("ANCHOR REGRESSION: wrong-zone verify returned {other:?}"),
    }

    // (d) Wrong secret (1-bit flip on byte 0).
    let mut bad_secret = secret;
    bad_secret[0] ^= 0x01;
    match verify_epoch_zone_key(&zone, &bad_secret, epoch, &key) {
        Ok(false) => {}
        other => panic!("ANCHOR REGRESSION: wrong-secret verify returned {other:?}"),
    }

    // (e) Wrong key (1-bit flip on byte 0).
    let mut bad_key_bytes = *key.as_bytes();
    bad_key_bytes[0] ^= 0x01;
    let bad_key = ZoneKey::from_bytes(bad_key_bytes);
    match verify_epoch_zone_key(&zone, &secret, epoch, &bad_key) {
        Ok(false) => {}
        other => panic!("ANCHOR REGRESSION: wrong-key verify returned {other:?}"),
    }

    // (f) Cross-zone keys differ.
    let other_key = PcsGroupState::derive_zone_key_for_epoch(&other_zone, &secret, epoch)
        .expect("ANCHOR: derive other zone");
    assert_ne!(
        key.as_bytes(),
        other_key.as_bytes(),
        "ANCHOR REGRESSION: zone binding lost — keys for distinct zones identical at same (secret, epoch)"
    );

    // (g) Determinism on the anchor.
    let key2 = PcsGroupState::derive_zone_key_for_epoch(&zone, &secret, epoch)
        .expect("ANCHOR: derive repeat");
    assert_eq!(
        key.as_bytes(),
        key2.as_bytes(),
        "ANCHOR REGRESSION: derive_zone_key_for_epoch non-deterministic"
    );
}
