#![no_main]

//! Fuzz target for `SessionDirection::as_u8` byte mapping +
//! `SessionKeys::mac_key` direction dispatch (session.rs:700-852).
//!
//! `SessionDirection::as_u8` returns 0x00 for InitiatorToResponder and
//! 0x01 for ResponderToInitiator. `SessionKeys::mac_key` returns the
//! per-direction MAC key. NOT directly fuzzed; covered transitively by
//! session_metamorphic which exercises the round-trip.
//!
//! A regression that swapped the byte values would silently break the
//! direction-byte input to every MAC computation, defeating the
//! reflection-defense MR (covered separately by session_metamorphic
//! MR-MAC-4).
//!
//! Properties asserted:
//!
//!   1. **as_u8 byte values**: InitiatorToResponder == 0x00,
//!      ResponderToInitiator == 0x01.
//!   2. **mac_key dispatch**: `mac_key(I2R) == &k_mac_i2r` and
//!      `mac_key(R2I) == &k_mac_r2i`.
//!   3. **mac_key byte-distinctness**: when the SessionKeys was
//!      constructed with distinct k_mac_i2r vs k_mac_r2i bytes,
//!      mac_key(I2R) != mac_key(R2I).
//!
//!   Once-gated anchors verify the exact byte mapping.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{SessionDirection, SessionKeys};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const KEY_SIZE: usize = 32;

static DIRECTION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    k_mac_i2r: [u8; KEY_SIZE],
    k_mac_r2i: [u8; KEY_SIZE],
    k_ctx: [u8; KEY_SIZE],
    direction_bit: bool,
}

fn pick_direction(b: bool) -> SessionDirection {
    if b {
        SessionDirection::InitiatorToResponder
    } else {
        SessionDirection::ResponderToInitiator
    }
}

fuzz_target!(|data: &[u8]| {
    DIRECTION_ANCHOR.call_once(assert_direction_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let direction = pick_direction(input.direction_bit);

    // ── PROPERTY 1: as_u8 byte values ─────────────────────────────────
    let byte = direction.as_u8();
    match direction {
        SessionDirection::InitiatorToResponder => {
            assert_eq!(byte, 0x00, "I2R as_u8 != 0x00");
        }
        SessionDirection::ResponderToInitiator => {
            assert_eq!(byte, 0x01, "R2I as_u8 != 0x01");
        }
    }

    // ── PROPERTY 2: mac_key dispatch ──────────────────────────────────
    let keys = SessionKeys {
        k_mac_i2r: input.k_mac_i2r,
        k_mac_r2i: input.k_mac_r2i,
        k_ctx: input.k_ctx,
    };

    assert_eq!(
        keys.mac_key(SessionDirection::InitiatorToResponder),
        &input.k_mac_i2r,
        "mac_key(I2R) did not return k_mac_i2r"
    );
    assert_eq!(
        keys.mac_key(SessionDirection::ResponderToInitiator),
        &input.k_mac_r2i,
        "mac_key(R2I) did not return k_mac_r2i"
    );

    // ── PROPERTY 3: byte-distinctness when fields differ ─────────────
    if input.k_mac_i2r != input.k_mac_r2i {
        assert_ne!(
            keys.mac_key(SessionDirection::InitiatorToResponder),
            keys.mac_key(SessionDirection::ResponderToInitiator),
            "mac_key dispatched to the same buffer for different directions \
             (I2R != R2I in input but mac_key returns same)"
        );
    }
});

/// Once-gated anchors verifying the exact byte mapping.
fn assert_direction_anchored() {
    // (a) Exact byte values per documentation.
    assert_eq!(
        SessionDirection::InitiatorToResponder.as_u8(),
        0x00,
        "ANCHOR REGRESSION: InitiatorToResponder.as_u8() != 0x00 — wire \
         format byte changed; reflection-defense MAC binding broken"
    );
    assert_eq!(
        SessionDirection::ResponderToInitiator.as_u8(),
        0x01,
        "ANCHOR REGRESSION: ResponderToInitiator.as_u8() != 0x01"
    );

    // (b) The two byte values are distinct.
    assert_ne!(
        SessionDirection::InitiatorToResponder.as_u8(),
        SessionDirection::ResponderToInitiator.as_u8(),
        "ANCHOR: I2R and R2I as_u8 collide"
    );

    // (c) Known SessionKeys returns the right buffer per direction.
    let keys = SessionKeys {
        k_mac_i2r: [0xAAu8; KEY_SIZE],
        k_mac_r2i: [0xBBu8; KEY_SIZE],
        k_ctx: [0xCCu8; KEY_SIZE],
    };
    assert_eq!(
        keys.mac_key(SessionDirection::InitiatorToResponder),
        &[0xAAu8; KEY_SIZE],
        "ANCHOR: mac_key(I2R) on known keys != [0xAA;32]"
    );
    assert_eq!(
        keys.mac_key(SessionDirection::ResponderToInitiator),
        &[0xBBu8; KEY_SIZE],
        "ANCHOR: mac_key(R2I) on known keys != [0xBB;32]"
    );
}
