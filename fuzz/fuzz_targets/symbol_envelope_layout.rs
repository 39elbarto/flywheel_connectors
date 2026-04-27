#![no_main]

//! Fuzz target for `derive_nonce12` / `derive_nonce24` / `build_symbol_aad`
//! byte-layout primitives (symbol_envelope.rs:138-193).
//!
//! These three pure functions feed AEAD encryption (ChaCha20-Poly1305 /
//! XChaCha20-Poly1305). A regression in any field's byte position would:
//!   - produce nonce reuse under the same key (catastrophic for
//!     ChaCha20-Poly1305 — leaks plaintext + lets attacker forge
//!     ciphertexts), OR
//!   - produce AAD mismatch and silent decryption failures across
//!     legitimate sender/receiver pairs (correctness-class but masks
//!     deeper protocol bugs).
//!
//! Existing fuzz coverage:
//!   - `symbol_envelope_decrypt` — exercises round-trip under the
//!     primitives but does NOT probe their layout invariants directly.
//!
//! Properties asserted:
//!
//!   1. **Determinism**: same inputs ⇒ same output bytes for all three
//!      primitives.
//!   2. **Bit-level injectivity (nonce12)**: distinct (frame_seq, esi)
//!      tuples MUST produce distinct 12-byte nonces.
//!   3. **Bit-level injectivity (nonce24)**: distinct
//!      (sender_instance_id, frame_seq, esi) tuples MUST produce
//!      distinct 24-byte nonces.
//!   4. **build_symbol_aad per-field binding**: changing any of
//!      (object_id, esi, k, zone_id_hash, zone_key_id, epoch_id) MUST
//!      change the AAD bytes.
//!   5. **Stable lengths**: nonce12=12 bytes, nonce24=24 bytes,
//!      AAD=86 bytes.
//!   6. **derive_nonce24 zero-padding**: bytes 20-23 always zero.
//!
//!   Once-gated regression anchors:
//!     (a) derive_nonce12(0x0807060504030201, 0x12111009) produces the
//!         exact 12-byte LE-encoded layout per documentation.
//!     (b) derive_nonce24(instance, frame_seq, esi) produces the exact
//!         24-byte layout including bytes 20-23 = 0.
//!     (c) build_symbol_aad with known SymbolContext produces 86 bytes
//!         with object_id at [0..32), esi at [32..36), k at [36..38),
//!         zone_id_hash at [38..70), zone_key_id at [70..78),
//!         epoch_id at [78..86).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, TailscaleNodeId, ZoneIdHash, ZoneKeyId};
use fcp_protocol::{
    SYMBOL_AAD_SIZE, SymbolContext, build_symbol_aad, derive_nonce12, derive_nonce24,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const NONCE12_LEN: usize = 12;
const NONCE24_LEN: usize = 24;

static LAYOUT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug, Clone)]
struct Input {
    frame_seq: u64,
    esi: u32,
    sender_instance_id: u64,
    /// Mutation discriminator for the AAD per-field binding MR.
    field_disc: u8,
    /// Seed bytes for SymbolContext.
    object_id: [u8; 32],
    k: u16,
    zone_id_hash: [u8; 32],
    zone_key_id: [u8; 8],
    epoch_id: u64,
}

fn make_ctx(input: &Input) -> SymbolContext {
    SymbolContext {
        object_id: ObjectId::from_bytes(input.object_id),
        esi: input.esi,
        k: input.k,
        zone_id_hash: ZoneIdHash::from_bytes(input.zone_id_hash),
        zone_key_id: ZoneKeyId::from_bytes(input.zone_key_id),
        epoch_id: input.epoch_id,
        sender_node_id: TailscaleNodeId::new("node-sender"),
        sender_instance_id: input.sender_instance_id,
        frame_seq: input.frame_seq,
    }
}

/// Mutate one binding-relevant SymbolContext field. Returns Some only
/// when the mutation actually changed an AAD-bound field.
fn mutate_aad_field(ctx: &SymbolContext, disc: u8) -> SymbolContext {
    let mut c = ctx.clone();
    match disc % 6 {
        0 => {
            let mut bytes = *c.object_id.as_bytes();
            bytes[0] ^= 0x01;
            c.object_id = ObjectId::from_bytes(bytes);
        }
        1 => c.esi ^= 1,
        2 => c.k ^= 1,
        3 => {
            let mut bytes = *c.zone_id_hash.as_bytes();
            bytes[0] ^= 0x01;
            c.zone_id_hash = ZoneIdHash::from_bytes(bytes);
        }
        4 => {
            let mut bytes = *c.zone_key_id.as_bytes();
            bytes[0] ^= 0x01;
            c.zone_key_id = ZoneKeyId::from_bytes(bytes);
        }
        _ => c.epoch_id ^= 1,
    }
    c
}

fuzz_target!(|data: &[u8]| {
    LAYOUT_ANCHOR.call_once(assert_layout_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // ── PROPERTY 1+5: derive_nonce12 determinism + length ─────────────
    let n12_a = derive_nonce12(input.frame_seq, input.esi);
    let n12_b = derive_nonce12(input.frame_seq, input.esi);
    assert_eq!(
        n12_a.as_bytes(),
        n12_b.as_bytes(),
        "derive_nonce12 not deterministic"
    );
    assert_eq!(n12_a.as_bytes().len(), NONCE12_LEN);

    // ── PROPERTY 2: nonce12 bit-level injectivity ─────────────────────
    let alt_seq = input.frame_seq.wrapping_add(1);
    let alt_esi = input.esi.wrapping_add(1);
    let n12_alt_seq = derive_nonce12(alt_seq, input.esi);
    let n12_alt_esi = derive_nonce12(input.frame_seq, alt_esi);
    if alt_seq != input.frame_seq {
        assert_ne!(
            n12_a.as_bytes(),
            n12_alt_seq.as_bytes(),
            "derive_nonce12 collision under different frame_seq — nonce reuse \
             surface for ChaCha20-Poly1305"
        );
    }
    if alt_esi != input.esi {
        assert_ne!(
            n12_a.as_bytes(),
            n12_alt_esi.as_bytes(),
            "derive_nonce12 collision under different esi — nonce reuse surface"
        );
    }

    // ── PROPERTY 1+5: derive_nonce24 determinism + length ─────────────
    let n24_a = derive_nonce24(input.sender_instance_id, input.frame_seq, input.esi);
    let n24_b = derive_nonce24(input.sender_instance_id, input.frame_seq, input.esi);
    assert_eq!(
        n24_a.as_bytes(),
        n24_b.as_bytes(),
        "derive_nonce24 not deterministic"
    );
    assert_eq!(n24_a.as_bytes().len(), NONCE24_LEN);

    // ── PROPERTY 6: derive_nonce24 zero-padding ───────────────────────
    let bytes24 = n24_a.as_bytes();
    assert_eq!(
        &bytes24[20..24],
        &[0u8; 4],
        "derive_nonce24 bytes 20-23 not zero-padded; got {:?}",
        &bytes24[20..24]
    );

    // ── PROPERTY 3: nonce24 bit-level injectivity ─────────────────────
    let alt_instance = input.sender_instance_id.wrapping_add(1);
    if alt_instance != input.sender_instance_id {
        let n24_alt_inst = derive_nonce24(alt_instance, input.frame_seq, input.esi);
        assert_ne!(
            n24_a.as_bytes(),
            n24_alt_inst.as_bytes(),
            "derive_nonce24 collision under different sender_instance_id — \
             cross-sender nonce-reuse surface for XChaCha20-Poly1305"
        );
    }

    // ── PROPERTY 1+5: build_symbol_aad determinism + length ───────────
    let ctx = make_ctx(&input);
    let aad_a = build_symbol_aad(&ctx);
    let aad_b = build_symbol_aad(&ctx);
    assert_eq!(aad_a, aad_b, "build_symbol_aad not deterministic");
    assert_eq!(aad_a.len(), SYMBOL_AAD_SIZE);

    // ── PROPERTY 4: per-field binding ────────────────────────────────
    let ctx_mutated = mutate_aad_field(&ctx, input.field_disc);
    let aad_mutated = build_symbol_aad(&ctx_mutated);
    if aad_mutated != aad_a {
        // Mutation actually changed AAD bytes — that's expected.
    } else {
        // Mutation didn't change AAD; check it really was a no-op
        // (e.g., XOR-ing 1 into a u16 that was already 1 produces 0,
        //  but the field still changed). We compare via match arms
        //  semantically: if the mutation failed to differ, that means
        //  the field was excluded from AAD.
        let raw_changed = match input.field_disc % 6 {
            0 => ctx.object_id != ctx_mutated.object_id,
            1 => ctx.esi != ctx_mutated.esi,
            2 => ctx.k != ctx_mutated.k,
            3 => ctx.zone_id_hash != ctx_mutated.zone_id_hash,
            4 => ctx.zone_key_id != ctx_mutated.zone_key_id,
            _ => ctx.epoch_id != ctx_mutated.epoch_id,
        };
        if raw_changed {
            panic!(
                "build_symbol_aad: changing field {} (disc={}) did NOT change \
                 AAD bytes — field dropped from AAD; AEAD authentication of that \
                 field is broken",
                [
                    "object_id",
                    "esi",
                    "k",
                    "zone_id_hash",
                    "zone_key_id",
                    "epoch_id"
                ][(input.field_disc % 6) as usize],
                input.field_disc % 6
            );
        }
    }
});

/// Once-gated regression anchors verifying the documented byte layouts
/// at exact positions.
fn assert_layout_anchored() {
    // (a) derive_nonce12(frame_seq=0x0807060504030201, esi=0x12111009)
    // Layout: [0..8) = frame_seq LE, [8..12) = esi LE.
    let n12 = derive_nonce12(0x0807_0605_0403_0201, 0x1211_1009);
    let bytes = n12.as_bytes();
    assert_eq!(
        &bytes[0..8],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "ANCHOR REGRESSION: derive_nonce12 frame_seq bytes (0..8) wrong; \
         expected LE 0x01..0x08; got {:?}",
        &bytes[0..8]
    );
    assert_eq!(
        &bytes[8..12],
        &[0x09, 0x10, 0x11, 0x12],
        "ANCHOR REGRESSION: derive_nonce12 esi bytes (8..12) wrong; \
         expected LE 0x09,0x10,0x11,0x12; got {:?}",
        &bytes[8..12]
    );

    // (b) derive_nonce24 layout: [0..8)=instance_id, [8..16)=frame_seq,
    // [16..20)=esi, [20..24)=zero.
    let n24 = derive_nonce24(0xAABB_CCDD_EEFF_0011, 0x0807_0605_0403_0201, 0x1211_1009);
    let bytes = n24.as_bytes();
    assert_eq!(
        &bytes[0..8],
        &[0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA],
        "ANCHOR REGRESSION: derive_nonce24 sender_instance_id bytes wrong"
    );
    assert_eq!(
        &bytes[8..16],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "ANCHOR REGRESSION: derive_nonce24 frame_seq bytes wrong"
    );
    assert_eq!(
        &bytes[16..20],
        &[0x09, 0x10, 0x11, 0x12],
        "ANCHOR REGRESSION: derive_nonce24 esi bytes wrong"
    );
    assert_eq!(
        &bytes[20..24],
        &[0u8; 4],
        "ANCHOR REGRESSION: derive_nonce24 zero-padding wrong"
    );

    // (c) build_symbol_aad layout: 86-byte fixed structure.
    let ctx = SymbolContext {
        object_id: ObjectId::from_bytes([0x11u8; 32]),
        esi: 0x1211_1009,
        k: 0xABCD,
        zone_id_hash: ZoneIdHash::from_bytes([0x22u8; 32]),
        zone_key_id: ZoneKeyId::from_bytes([0x33u8; 8]),
        epoch_id: 0xFFEE_DDCC_BBAA_9988,
        sender_node_id: TailscaleNodeId::new("anchor"),
        sender_instance_id: 0,
        frame_seq: 0,
    };
    let aad = build_symbol_aad(&ctx);
    assert_eq!(aad.len(), SYMBOL_AAD_SIZE);
    assert_eq!(
        &aad[0..32],
        &[0x11u8; 32],
        "ANCHOR REGRESSION: build_symbol_aad object_id position [0..32) wrong"
    );
    assert_eq!(
        &aad[32..36],
        &[0x09, 0x10, 0x11, 0x12],
        "ANCHOR REGRESSION: build_symbol_aad esi position [32..36) wrong"
    );
    assert_eq!(
        &aad[36..38],
        &[0xCD, 0xAB],
        "ANCHOR REGRESSION: build_symbol_aad k position [36..38) wrong"
    );
    assert_eq!(
        &aad[38..70],
        &[0x22u8; 32],
        "ANCHOR REGRESSION: build_symbol_aad zone_id_hash position [38..70) wrong"
    );
    assert_eq!(
        &aad[70..78],
        &[0x33u8; 8],
        "ANCHOR REGRESSION: build_symbol_aad zone_key_id position [70..78) wrong"
    );
    assert_eq!(
        &aad[78..86],
        &[0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        "ANCHOR REGRESSION: build_symbol_aad epoch_id position [78..86) wrong"
    );
}
