#![no_main]

//! Fuzz target for `fcp_protocol::derive_session_keys` binding properties.
//!
//! The handshake's KDF is the only thing that ties matching session keys
//! to the negotiated transcript. Any input field that fails to flow into
//! the HKDF info string would let an attacker who controls *that* field
//! force key collisions across distinct sessions:
//!
//!   - `session_id` ↔ HKDF salt
//!   - `(initiator_id, responder_id, hello_nonce, ack_nonce)` ↔ HKDF info
//!
//! Properties asserted:
//!
//!   1. **Determinism**: same inputs ⇒ identical SessionKeys.
//!   2. **Direction-key inequality**: k_mac_i2r ≠ k_mac_r2i, so a MAC
//!      computed under one direction does not satisfy verification in
//!      the other (closes the trivial reflection surface that
//!      session_metamorphic MR-MAC-4 covers from the verify side).
//!   3. **Hello-nonce binding**: bit-flipping `hello_nonce` MUST
//!      change the derived keys.
//!   4. **Ack-nonce binding**: same for `ack_nonce`.
//!   5. **Node-id-swap binding**: swapping `initiator_node_id` ↔
//!      `responder_node_id` MUST change the keys (the HKDF info is
//!      direction-asymmetric so peer A cannot impersonate peer B by
//!      reusing a derivation).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::TailscaleNodeId;
use fcp_crypto::X25519SecretKey;
use fcp_protocol::{MeshSessionId, SessionNonce, derive_session_keys};
use libfuzzer_sys::fuzz_target;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;

#[derive(Arbitrary, Debug)]
struct Input {
    sk_a: [u8; KEY_SIZE],
    sk_b: [u8; KEY_SIZE],
    session_id: [u8; NONCE_SIZE],
    hello_nonce: [u8; NONCE_SIZE],
    ack_nonce: [u8; NONCE_SIZE],
    /// Bit index for the nonce-mutation MRs.
    bitflip_index: u8,
    /// Choose initiator/responder identifier from a fixed canonical pair
    /// to avoid recomputing validate_canonical_id on every iteration.
    swap_ids: bool,
}

fn flip_bit(bytes: &mut [u8], bit_index: usize) {
    let byte = bit_index / 8;
    let mask = 1u8 << (bit_index % 8);
    bytes[byte] ^= mask;
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Build a non-degenerate ECDH shared secret from arbitrary key seeds.
    // Bail when DH rejects (low-order pubkey) — that branch is covered
    // by fuzz_x25519_dh and is not what this target probes.
    let sk_a = X25519SecretKey::from_bytes(input.sk_a);
    let sk_b = X25519SecretKey::from_bytes(input.sk_b);
    let Ok(shared) = sk_a.diffie_hellman(&sk_b.public_key()) else {
        return;
    };

    // Canonical, validation-safe identifiers — using `new` not `try_new`
    // since these are compile-time-known strings.
    let init_id = TailscaleNodeId::new("node-initiator");
    let resp_id = TailscaleNodeId::new("node-responder");

    let session_id = MeshSessionId(input.session_id);
    let hello_nonce = SessionNonce(input.hello_nonce);
    let ack_nonce = SessionNonce(input.ack_nonce);

    let derive = |hello_n: &SessionNonce,
                  ack_n: &SessionNonce,
                  init: &TailscaleNodeId,
                  resp: &TailscaleNodeId| {
        derive_session_keys(&shared, &session_id, init, resp, hello_n, ack_n)
            .expect("derive_session_keys must succeed for non-degenerate inputs")
    };

    let baseline = derive(&hello_nonce, &ack_nonce, &init_id, &resp_id);

    // ── PROPERTY 1: determinism ────────────────────────────────────────
    let baseline2 = derive(&hello_nonce, &ack_nonce, &init_id, &resp_id);
    assert_eq!(
        baseline.k_mac_i2r, baseline2.k_mac_i2r,
        "derive_session_keys is not deterministic on k_mac_i2r"
    );
    assert_eq!(
        baseline.k_mac_r2i, baseline2.k_mac_r2i,
        "derive_session_keys is not deterministic on k_mac_r2i"
    );
    assert_eq!(
        baseline.k_ctx, baseline2.k_ctx,
        "derive_session_keys is not deterministic on k_ctx"
    );

    // ── PROPERTY 2: direction-key inequality ───────────────────────────
    // The HKDF expansion produces 96 bytes split 32/32/32 into i2r/r2i/ctx.
    // Identical 32-byte slices at distinct HKDF output offsets requires
    // either an HKDF collision (cryptographically infeasible) or a real
    // regression (e.g., the slice ranges accidentally overlap). Either
    // way the keys MUST differ.
    assert_ne!(
        baseline.k_mac_i2r, baseline.k_mac_r2i,
        "k_mac_i2r equal to k_mac_r2i — direction-aware MAC collapses to direction-blind"
    );
    assert_ne!(
        baseline.k_mac_i2r, baseline.k_ctx,
        "k_mac_i2r equal to k_ctx — MAC and context keys aliased"
    );
    assert_ne!(
        baseline.k_mac_r2i, baseline.k_ctx,
        "k_mac_r2i equal to k_ctx — MAC and context keys aliased"
    );

    // ── PROPERTY 3: hello-nonce binding ────────────────────────────────
    let mut alt_hello_bytes = input.hello_nonce;
    let bit = (input.bitflip_index as usize) % (NONCE_SIZE * 8);
    flip_bit(&mut alt_hello_bytes, bit);
    if alt_hello_bytes != input.hello_nonce {
        let alt = derive(
            &SessionNonce(alt_hello_bytes),
            &ack_nonce,
            &init_id,
            &resp_id,
        );
        assert_ne!(
            baseline.k_mac_i2r, alt.k_mac_i2r,
            "hello_nonce bit-flip did not change k_mac_i2r"
        );
        assert_ne!(
            baseline.k_ctx, alt.k_ctx,
            "hello_nonce bit-flip did not change k_ctx"
        );
    }

    // ── PROPERTY 4: ack-nonce binding ──────────────────────────────────
    let mut alt_ack_bytes = input.ack_nonce;
    flip_bit(&mut alt_ack_bytes, bit);
    if alt_ack_bytes != input.ack_nonce {
        let alt = derive(
            &hello_nonce,
            &SessionNonce(alt_ack_bytes),
            &init_id,
            &resp_id,
        );
        assert_ne!(
            baseline.k_mac_i2r, alt.k_mac_i2r,
            "ack_nonce bit-flip did not change k_mac_i2r"
        );
        assert_ne!(
            baseline.k_ctx, alt.k_ctx,
            "ack_nonce bit-flip did not change k_ctx"
        );
    }

    // ── PROPERTY 5: node-id-swap binding ───────────────────────────────
    // Swap init/resp IDs: HKDF info encodes them in order, so the
    // resulting keys MUST diverge.
    if input.swap_ids {
        let swapped = derive(&hello_nonce, &ack_nonce, &resp_id, &init_id);
        assert_ne!(
            baseline.k_mac_i2r, swapped.k_mac_i2r,
            "swapping (initiator, responder) did not change k_mac_i2r — \
             HKDF info is direction-symmetric, opens impersonation surface"
        );
    }
});
