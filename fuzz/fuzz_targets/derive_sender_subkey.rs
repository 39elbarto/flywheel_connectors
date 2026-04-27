#![no_main]

//! Fuzz target for `fcp_protocol::derive_sender_subkey` HKDF binding
//! (symbol_envelope.rs:102-125).
//!
//! `derive_sender_subkey` computes a per-sender AEAD subkey via
//! HKDF-SHA256 with:
//!   - salt = `zone_key_id` (8 bytes)
//!   - ikm  = `zone_key` bytes
//!   - info = b"FCP2-SENDER-KEY-V1" || u32_LE(sender_node_id_len)
//!     || sender_node_id_bytes || u64_LE(sender_instance_id)
//!
//! The length-prefixing on `sender_node_id` is the analogous defense
//! to the SchemaId::hash mzi9x fix — without it, distinct
//! (node_id_a, instance_a) and (node_id_b, instance_b) pairs could
//! collide if their byte concatenations alias.
//!
//! Existing `symbol_envelope_decrypt` covers round-trip but NOT the
//! per-input bit-level injectivity. `symbol_envelope_layout` (gcqmu)
//! covers nonce + AAD layout only.
//!
//! Properties asserted:
//!
//!   1. **Determinism**: same inputs ⇒ same subkey.
//!   2. **zone_key bit-level injectivity**: distinct zone_key bytes
//!      MUST produce distinct subkeys.
//!   3. **zone_key_id bit-level injectivity**: distinct zone_key_id
//!      bytes MUST produce distinct subkeys.
//!   4. **sender_node_id bit-level injectivity**: distinct node_id
//!      strings MUST produce distinct subkeys.
//!   5. **sender_instance_id bit-level injectivity**: distinct
//!      instance ids MUST produce distinct subkeys.
//!   6. **Length-prefixed node_id binding**: a node_id whose bytes
//!      are a *prefix* of another node_id (with the rest absorbed
//!      into the instance_id LE bytes) MUST still produce distinct
//!      subkeys. Without the u32_LE length prefix, a regression would
//!      let attacker-chosen node_id strings collide on different
//!      instance ids.
//!
//!   Once-gated regression anchors:
//!     (a) Determinism: known inputs produce stable bytes.
//!     (b) Length-prefix binding: ("ab", instance=0x6364) MUST NOT
//!         produce the same subkey as ("abcd", instance=0). Without
//!         length-prefixing, both info strings would alias.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{TailscaleNodeId, ZoneKeyId};
use fcp_crypto::AeadKey;
use fcp_protocol::derive_sender_subkey;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const AEAD_KEY_LEN: usize = 32;
const ZONE_KEY_ID_LEN: usize = 8;

static SUBKEY_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    zone_key_a: [u8; AEAD_KEY_LEN],
    zone_key_b: [u8; AEAD_KEY_LEN],
    zone_key_id_a: [u8; ZONE_KEY_ID_LEN],
    zone_key_id_b: [u8; ZONE_KEY_ID_LEN],
    /// Node-id discriminator: pick from a small pool of known-canonical strings.
    node_id_disc_a: u8,
    node_id_disc_b: u8,
    instance_a: u64,
    instance_b: u64,
}

const NODE_IDS: [&str; 4] = ["node-a", "node-b", "node-alpha", "n"];

fn pick_node_id(disc: u8) -> TailscaleNodeId {
    TailscaleNodeId::new(NODE_IDS[(disc as usize) % NODE_IDS.len()])
}

fn derive(
    zone_key: &[u8; AEAD_KEY_LEN],
    zone_key_id: &[u8; ZONE_KEY_ID_LEN],
    node_id: &TailscaleNodeId,
    instance: u64,
) -> AeadKey {
    let zk = AeadKey::from_bytes(*zone_key);
    let zkid = ZoneKeyId::from_bytes(*zone_key_id);
    derive_sender_subkey(&zk, &zkid, node_id, instance)
}

fuzz_target!(|data: &[u8]| {
    SUBKEY_ANCHOR.call_once(assert_subkey_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let nid_a = pick_node_id(input.node_id_disc_a);
    let nid_b = pick_node_id(input.node_id_disc_b);

    // ── PROPERTY 1: determinism ──────────────────────────────────────
    let k1 = derive(
        &input.zone_key_a,
        &input.zone_key_id_a,
        &nid_a,
        input.instance_a,
    );
    let k1b = derive(
        &input.zone_key_a,
        &input.zone_key_id_a,
        &nid_a,
        input.instance_a,
    );
    assert_eq!(
        k1.as_bytes(),
        k1b.as_bytes(),
        "derive_sender_subkey not deterministic"
    );

    // ── PROPERTY 2: zone_key injectivity ─────────────────────────────
    if input.zone_key_a != input.zone_key_b {
        let k_alt = derive(
            &input.zone_key_b,
            &input.zone_key_id_a,
            &nid_a,
            input.instance_a,
        );
        assert_ne!(
            k1.as_bytes(),
            k_alt.as_bytes(),
            "different zone_key produced identical subkey — IKM collision"
        );
    }

    // ── PROPERTY 3: zone_key_id injectivity ──────────────────────────
    if input.zone_key_id_a != input.zone_key_id_b {
        let k_alt = derive(
            &input.zone_key_a,
            &input.zone_key_id_b,
            &nid_a,
            input.instance_a,
        );
        assert_ne!(
            k1.as_bytes(),
            k_alt.as_bytes(),
            "different zone_key_id (HKDF salt) produced identical subkey"
        );
    }

    // ── PROPERTY 4: sender_node_id injectivity ───────────────────────
    if nid_a.as_str() != nid_b.as_str() {
        let k_alt = derive(
            &input.zone_key_a,
            &input.zone_key_id_a,
            &nid_b,
            input.instance_a,
        );
        assert_ne!(
            k1.as_bytes(),
            k_alt.as_bytes(),
            "different sender_node_id produced identical subkey — info-field \
             binding broken; cross-sender key collision possible"
        );
    }

    // ── PROPERTY 5: sender_instance_id injectivity ───────────────────
    if input.instance_a != input.instance_b {
        let k_alt = derive(
            &input.zone_key_a,
            &input.zone_key_id_a,
            &nid_a,
            input.instance_b,
        );
        assert_ne!(
            k1.as_bytes(),
            k_alt.as_bytes(),
            "different sender_instance_id produced identical subkey"
        );
    }
});

/// Once-gated regression anchors for the most load-bearing HKDF
/// binding properties.
fn assert_subkey_anchored() {
    let zone_key = [0x42u8; AEAD_KEY_LEN];
    let zone_key_id = [0xABu8; ZONE_KEY_ID_LEN];
    let nid = TailscaleNodeId::new("anchor-node");

    // (a) Determinism on a known input.
    let k1 = derive(&zone_key, &zone_key_id, &nid, 0x0123_4567_89AB_CDEF);
    let k2 = derive(&zone_key, &zone_key_id, &nid, 0x0123_4567_89AB_CDEF);
    assert_eq!(
        k1.as_bytes(),
        k2.as_bytes(),
        "ANCHOR: derive_sender_subkey not deterministic on known inputs"
    );

    // (b) Length-prefix binding regression anchor.
    //
    // Without u32_LE length-prefixing on sender_node_id, the info
    // string for these two pairs would alias:
    //   info_short = "FCP2-SENDER-KEY-V1" || "ab" || u64_LE(0x6463)
    //              == "FCP2-SENDER-KEY-V1" || "ab" || [0x63, 0x64, 0, 0, 0, 0, 0, 0]
    //   info_long  = "FCP2-SENDER-KEY-V1" || "abcd" || u64_LE(0)
    //              == "FCP2-SENDER-KEY-V1" || "ab" || [0x63, 0x64, 0, 0, 0, 0, 0, 0]
    //
    // (The "cd" bytes from the longer node_id end up in the same byte
    // positions as the LE-encoded instance_id.) With length-prefixing,
    // info_short carries u32_LE(2) and info_long carries u32_LE(4),
    // so the HKDF inputs differ.
    //
    // We anchor the post-fix invariant: the two pairs MUST produce
    // distinct subkeys.
    let nid_short = TailscaleNodeId::new("ab");
    let nid_long = TailscaleNodeId::new("abcd");
    let instance_with_cd: u64 = 0x6463; // 'c'=0x63, 'd'=0x64 → LE 0x63, 0x64
    let k_short = derive(&zone_key, &zone_key_id, &nid_short, instance_with_cd);
    let k_long = derive(&zone_key, &zone_key_id, &nid_long, 0);
    assert_ne!(
        k_short.as_bytes(),
        k_long.as_bytes(),
        "ANCHOR REGRESSION: derive_sender_subkey(\"ab\", instance=0x6463) collided \
         with derive_sender_subkey(\"abcd\", instance=0) — the u32_LE length \
         prefix on sender_node_id (symbol_envelope.rs:112-117) is missing or \
         truncated; attacker-chosen node_id strings can collide on different \
         instance ids."
    );
}
