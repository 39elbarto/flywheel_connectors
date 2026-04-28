#![no_main]

//! Fuzz target for `fcp_crypto::mac` BLAKE3 keyed MAC family
//! (mac.rs:21-194).
//!
//! Covers `MacKey::try_from_slice`, `Blake3Mac::{compute, compute_full,
//! verify, verify_full}`, `IncrementalMac`, and the free-function
//! convenience layer (`blake3_mac`, `blake3_mac_full`,
//! `blake3_mac_verify`). NOT covered as a discrete unit by any
//! existing fuzz target — the FCP2 frame-authentication primitive
//! that protects every session frame body has only `cargo test`
//! coverage today.
//!
//! A regression that:
//!   - changed the truncation policy (full → 16 bytes) would create a
//!     soundness gap between `compute` and `compute_full`.
//!   - made `IncrementalMac` finalize differently from one-shot
//!     `Blake3Mac::compute` would silently break any caller that
//!     authenticates a frame in pieces (header || payload).
//!   - dropped key/message binding (e.g. cached the previous tag
//!     during in-place mutation) would let an attacker reuse one
//!     authenticated frame's tag for another.
//!   - returned `Ok(())` for a wrong tag would defeat authentication
//!     altogether.
//!
//! Properties asserted:
//!
//!   1. **Compute → verify round-trip** (16-byte): for any key + msg,
//!      `Blake3Mac::verify(msg, &compute(msg))` returns `Ok(())`.
//!   2. **Compute → verify round-trip** (32-byte): same for the full
//!      tag width.
//!   3. **Truncation invariant**: `compute(m)[..16] ==
//!      compute_full(m)[..16]`.
//!   4. **Incremental == one-shot**: feeding `IncrementalMac` the same
//!      bytes in (potentially many) `update` chunks yields the same
//!      tag as `Blake3Mac::compute` over the concatenation, for both
//!      truncated and full sizes.
//!   5. **Free function == method**: `blake3_mac == compute`,
//!      `blake3_mac_full == compute_full`, `blake3_mac_verify ==
//!      verify`.
//!   6. **Wrong-tag rejection**: a single-bit flip on a valid tag
//!      MUST cause `verify` to return
//!      `CryptoError::SignatureVerificationFailed`.
//!   7. **Wrong-key rejection**: computing with a 1-bit-flipped key
//!      MUST produce a different tag.
//!   8. **Wrong-message rejection**: a single-byte mutation in a
//!      non-empty message MUST produce a different tag.
//!   9. **`MacKey::try_from_slice` length gate**: any non-32 byte
//!      slice MUST yield
//!      `CryptoError::InvalidKeyLength { expected: 32, actual }`.
//!  10. **`MacKey::try_from_slice` round-trip**: a 32-byte slice
//!      yields a key whose `as_bytes()` equals the input verbatim.
//!
//!   Once-gated anchors verify boundary lengths, the truncation
//!   relationship, and free-function/method agreement on a fixed
//!   key+message.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::mac::{
    BLAKE3_MAC_SIZE, Blake3Mac, IncrementalMac, MAC_KEY_SIZE, MAC_SIZE, MacKey, blake3_mac,
    blake3_mac_full, blake3_mac_verify,
};
use fcp_crypto::{CryptoError, CryptoResult};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static MAC_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    key_bytes: [u8; MAC_KEY_SIZE],
    message: Vec<u8>,
    /// Chunk sizes for IncrementalMac path (saturated to message len).
    chunk_lens: Vec<u8>,
    /// Index of the byte we'll mutate in the wrong-message test (mod len).
    mutate_idx: u8,
    /// Bit position (0..32) of the bit we'll flip in the wrong-key test.
    key_flip_byte: u8,
    /// Bit position (0..16) of the bit we'll flip in the wrong-tag test.
    tag_flip_byte: u8,
    /// Slice we'll pass to MacKey::try_from_slice.
    arbitrary_slice: Vec<u8>,
}

const MAX_MSG: usize = 4096;
const MAX_CHUNKS: usize = 32;
const MAX_SLICE: usize = 256;

fuzz_target!(|data: &[u8]| {
    MAC_ANCHOR.call_once(assert_mac_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.message.len() > MAX_MSG
        || input.chunk_lens.len() > MAX_CHUNKS
        || input.arbitrary_slice.len() > MAX_SLICE
    {
        return;
    }

    let key = MacKey::from_bytes(input.key_bytes);
    let mac = Blake3Mac::new(&key);

    // ── PROPERTY 1: 16-byte round-trip ──────────────────────────────────
    let tag = mac.compute(&input.message);
    mac.verify(&input.message, &tag)
        .expect("compute → verify MUST round-trip");

    // ── PROPERTY 2: 32-byte round-trip ──────────────────────────────────
    let tag_full = mac.compute_full(&input.message);
    mac.verify_full(&input.message, &tag_full)
        .expect("compute_full → verify_full MUST round-trip");

    // ── PROPERTY 3: truncation invariant ───────────────────────────────
    assert_eq!(
        tag.as_slice(),
        &tag_full[..MAC_SIZE],
        "compute(m) MUST equal compute_full(m)[..16]"
    );

    // ── PROPERTY 4: incremental == one-shot ─────────────────────────────
    let mut incremental = IncrementalMac::new(&key);
    let mut offset = 0;
    for &raw_chunk in &input.chunk_lens {
        if offset >= input.message.len() {
            break;
        }
        // raw_chunk is u8 ∈ 0..=255; clamp into [1, remaining]
        let remaining = input.message.len() - offset;
        let chunk = (usize::from(raw_chunk).max(1)).min(remaining);
        incremental.update(&input.message[offset..offset + chunk]);
        offset += chunk;
    }
    if offset < input.message.len() {
        incremental.update(&input.message[offset..]);
    }
    let inc_tag = incremental.finalize();
    assert_eq!(
        inc_tag, tag,
        "IncrementalMac diverged from one-shot Blake3Mac::compute"
    );

    // Same for full tag size.
    let mut incremental_full = IncrementalMac::new(&key);
    incremental_full.update(&input.message);
    let inc_tag_full = incremental_full.finalize_full();
    assert_eq!(
        inc_tag_full, tag_full,
        "IncrementalMac::finalize_full diverged from compute_full"
    );

    // ── PROPERTY 5: free function == method ────────────────────────────
    assert_eq!(
        blake3_mac(&key, &input.message),
        tag,
        "blake3_mac diverged from Blake3Mac::compute"
    );
    assert_eq!(
        blake3_mac_full(&key, &input.message),
        tag_full,
        "blake3_mac_full diverged from Blake3Mac::compute_full"
    );
    blake3_mac_verify(&key, &input.message, &tag)
        .expect("blake3_mac_verify MUST accept compute(m)");

    // ── PROPERTY 6: wrong-tag rejection ────────────────────────────────
    let mut bad_tag = tag;
    let flip_byte = (input.tag_flip_byte as usize) % MAC_SIZE;
    bad_tag[flip_byte] ^= 0x01;
    match mac.verify(&input.message, &bad_tag) {
        Err(CryptoError::SignatureVerificationFailed) => {}
        other => {
            panic!("verify on flipped tag returned {other:?}; expected SignatureVerificationFailed")
        }
    }
    match blake3_mac_verify(&key, &input.message, &bad_tag) {
        Err(CryptoError::SignatureVerificationFailed) => {}
        other => panic!(
            "blake3_mac_verify on flipped tag returned {other:?}; expected SignatureVerificationFailed"
        ),
    }

    // ── PROPERTY 7: wrong-key rejection ────────────────────────────────
    let mut other_key_bytes = input.key_bytes;
    let key_byte = (input.key_flip_byte as usize) % MAC_KEY_SIZE;
    other_key_bytes[key_byte] ^= 0x01;
    let other_key = MacKey::from_bytes(other_key_bytes);
    let other_tag = Blake3Mac::new(&other_key).compute(&input.message);
    assert_ne!(
        other_tag, tag,
        "Blake3Mac with 1-bit-flipped key produced identical tag"
    );

    // ── PROPERTY 8: wrong-message rejection ────────────────────────────
    if !input.message.is_empty() {
        let mut other_msg = input.message.clone();
        let idx = (input.mutate_idx as usize) % other_msg.len();
        other_msg[idx] ^= 0x01;
        let alt_tag = mac.compute(&other_msg);
        assert_ne!(
            alt_tag, tag,
            "Blake3Mac with 1-bit-flipped message produced identical tag"
        );
    }

    // ── PROPERTY 9 + 10: MacKey::try_from_slice ─────────────────────────
    let result: CryptoResult<MacKey> = MacKey::try_from_slice(&input.arbitrary_slice);
    match result {
        Ok(k) => {
            assert_eq!(
                input.arbitrary_slice.len(),
                MAC_KEY_SIZE,
                "try_from_slice accepted len {} (expected 32)",
                input.arbitrary_slice.len()
            );
            assert_eq!(
                k.as_bytes().as_slice(),
                input.arbitrary_slice.as_slice(),
                "try_from_slice + as_bytes lost data"
            );
        }
        Err(CryptoError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, MAC_KEY_SIZE, "InvalidKeyLength.expected != 32");
            assert_eq!(
                actual,
                input.arbitrary_slice.len(),
                "InvalidKeyLength.actual carried wrong byte count"
            );
            assert_ne!(
                input.arbitrary_slice.len(),
                MAC_KEY_SIZE,
                "try_from_slice rejected a 32-byte slice"
            );
        }
        Err(other) => panic!("try_from_slice returned unexpected error {other:?}"),
    }

    // BLAKE3_MAC_SIZE used implicitly via tag_full type.
    assert_eq!(BLAKE3_MAC_SIZE, 32, "BLAKE3_MAC_SIZE constant changed");
});

/// Once-gated anchors verifying truncation, free-function/method
/// agreement, and length-gate boundaries on hand-picked inputs.
fn assert_mac_anchored() {
    // (a) Truncation invariant on a known key/message pair.
    let key_bytes = [0x42u8; MAC_KEY_SIZE];
    let key = MacKey::from_bytes(key_bytes);
    let msg = b"FCP2 anchor message";
    let m = Blake3Mac::new(&key);
    let t16 = m.compute(msg);
    let t32 = m.compute_full(msg);
    assert_eq!(
        t16.as_slice(),
        &t32[..MAC_SIZE],
        "ANCHOR REGRESSION: compute(m) != compute_full(m)[..16] — truncation policy changed"
    );

    // (b) Free function == method on the same input.
    assert_eq!(
        blake3_mac(&key, msg),
        t16,
        "ANCHOR: blake3_mac diverged from Blake3Mac::compute"
    );
    assert_eq!(
        blake3_mac_full(&key, msg),
        t32,
        "ANCHOR: blake3_mac_full diverged from Blake3Mac::compute_full"
    );
    blake3_mac_verify(&key, msg, &t16).expect("ANCHOR: blake3_mac_verify on valid tag");

    // (c) Wrong-tag rejection (flip first byte).
    let mut bad = t16;
    bad[0] ^= 0xFF;
    match m.verify(msg, &bad) {
        Err(CryptoError::SignatureVerificationFailed) => {}
        other => panic!("ANCHOR: verify on bit-flipped tag returned {other:?}"),
    }

    // (d) Incremental == one-shot on a chunked anchor message.
    let mut inc = IncrementalMac::new(&key);
    inc.update(b"FCP2 ");
    inc.update(b"anchor ");
    inc.update(b"message");
    assert_eq!(
        inc.finalize(),
        t16,
        "ANCHOR REGRESSION: chunked IncrementalMac differs from one-shot"
    );

    // (e) MacKey::try_from_slice boundary lengths.
    match MacKey::try_from_slice(&[]) {
        Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        }) => {}
        other => {
            panic!("ANCHOR: empty slice MacKey expected InvalidKeyLength{{32,0}}, got {other:?}")
        }
    }
    match MacKey::try_from_slice(&[0u8; 31]) {
        Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 31,
        }) => {}
        other => panic!("ANCHOR: 31-byte MacKey expected InvalidKeyLength{{32,31}}, got {other:?}"),
    }
    match MacKey::try_from_slice(&[0u8; 33]) {
        Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 33,
        }) => {}
        other => panic!("ANCHOR: 33-byte MacKey expected InvalidKeyLength{{32,33}}, got {other:?}"),
    }
    let k = MacKey::try_from_slice(&[0xCDu8; 32]).expect("ANCHOR: 32-byte slice must accept");
    assert_eq!(
        k.as_bytes(),
        &[0xCDu8; 32],
        "ANCHOR: 32-byte MacKey bytes diverged"
    );
}
