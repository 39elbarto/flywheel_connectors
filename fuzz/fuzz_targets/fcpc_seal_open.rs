#![no_main]

//! Fuzz target for `FcpcFrame::seal` / `open` AEAD round-trip + AAD-binding
//! (fcpc.rs:169-294).
//!
//! `FcpcFrame::seal` wraps the control-plane payload in ChaCha20-Poly1305
//! with AAD = session_id || seq || flags (build_fcpc_aad fcpc.rs:311-317)
//! and a directional nonce derived from (seq, direction). `open` reverses
//! the operation under the same key + AAD.
//!
//! Existing `fuzz_fcpc_frame` covers decode panic-freedom + semantic
//! invariants on accepted frames. NOT covered:
//!   - seal/open round-trip
//!   - Per-AAD-field binding (session_id, seq, flags)
//!   - Direction binding (nonce.byte[0] = direction)
//!   - Key binding
//!   - Tamper rejection on ciphertext / tag
//!   - check_replay's tie-in with the FcpcFrame layer
//!
//! A regression in seal/open could:
//!   - drop direction from nonce → reflection attack: a packet sent
//!     by the initiator could be replayed back as if from the responder
//!   - drop session_id from AAD → cross-session frame splice
//!   - drop seq from AAD → replay protection bypass at the AEAD layer
//!     (separate from the ReplayWindow check)
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: open(direction, key, seal(direction, key, p)) == p.
//!   2. **Direction binding**: a frame sealed I→R MUST NOT open R→I.
//!   3. **Key binding**: open under a different k_ctx MUST fail.
//!   4. **Session-id binding (AAD)**: tampering header.session_id MUST
//!      cause open to fail.
//!   5. **Seq binding (nonce + AAD)**: tampering header.seq MUST cause
//!      open to fail.
//!   6. **Flags binding (AAD)**: tampering header.flags MUST cause open
//!      to fail.
//!   7. **Tamper rejection**: bit-flipping any byte of ciphertext OR
//!      tag MUST cause open to fail.
//!   8. **Encode/decode round-trip**: decode(encode(seal(p))) yields a
//!      frame whose open returns p.
//!   9. **check_replay rejects same seq twice**.
//!
//!   Once-gated regression anchors:
//!     (a) Direction reflection attack: I→R sealed frame opens cleanly
//!         under I→R but MUST fail under R→I.
//!     (b) Session-id splice: same seq + same key + different session_id
//!         MUST fail.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{
    FcpcFrame, FcpcFrameFlags, MeshSessionId, ReplayWindow, SESSION_ID_SIZE, SessionDirection,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const KEY_SIZE: usize = 32;

static FCPC_AEAD_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    session_id: [u8; SESSION_ID_SIZE],
    seq: u64,
    plaintext: Vec<u8>,
    k_ctx: [u8; KEY_SIZE],
    alt_k_ctx: [u8; KEY_SIZE],
    direction_bit: bool,
    /// Discriminator for which AAD field to tamper.
    aad_disc: u8,
    /// Bit index for ciphertext/tag tamper.
    tamper_index: u32,
    /// Tamper target: 0 = ciphertext, 1 = tag.
    tamper_target: bool,
}

const PLAINTEXT_CAP: usize = 1024;

fuzz_target!(|data: &[u8]| {
    FCPC_AEAD_ANCHOR.call_once(assert_fcpc_aead_anchored);

    let mut u = Unstructured::new(data);
    let Ok(mut input) = Input::arbitrary(&mut u) else {
        return;
    };

    if input.plaintext.len() > PLAINTEXT_CAP {
        input.plaintext.truncate(PLAINTEXT_CAP);
    }

    let session_id = MeshSessionId(input.session_id);
    let direction = if input.direction_bit {
        SessionDirection::InitiatorToResponder
    } else {
        SessionDirection::ResponderToInitiator
    };
    let opposite = match direction {
        SessionDirection::InitiatorToResponder => SessionDirection::ResponderToInitiator,
        SessionDirection::ResponderToInitiator => SessionDirection::InitiatorToResponder,
    };

    // ── PROPERTY 1: round-trip ────────────────────────────────────────
    let frame = match FcpcFrame::seal(
        session_id,
        input.seq,
        direction,
        FcpcFrameFlags::default(),
        &input.plaintext,
        &input.k_ctx,
    ) {
        Ok(f) => f,
        Err(_) => return,
    };

    let opened = frame
        .open(direction, &input.k_ctx)
        .expect("seal then open with same direction/key MUST succeed");
    assert_eq!(
        opened, input.plaintext,
        "seal→open round-trip lost or altered plaintext"
    );

    // ── PROPERTY 2: direction binding ─────────────────────────────────
    match frame.open(opposite, &input.k_ctx) {
        Err(_) => {}
        Ok(_) => panic!(
            "seal direction={direction:?} opened under direction={opposite:?} — \
             reflection attack surface re-opened (nonce direction byte dropped)"
        ),
    }

    // ── PROPERTY 3: key binding ───────────────────────────────────────
    if input.alt_k_ctx != input.k_ctx {
        match frame.open(direction, &input.alt_k_ctx) {
            Err(_) => {}
            Ok(_) => panic!("frame opened under wrong k_ctx — AEAD key binding broken"),
        }
    }

    // ── PROPERTY 4-6: AAD per-field binding ───────────────────────────
    let mut tampered = frame.clone();
    let mut header_changed = true;
    match input.aad_disc % 3 {
        0 => tampered.header.session_id.0[0] ^= 0x01,
        1 => tampered.header.seq ^= 1,
        _ => {
            // Toggle ENCRYPTED flag — the only flag that's part of the
            // AAD and changeable without tripping InvalidFlags. We
            // preserve the COMPRESSED bit untouched.
            // Actually, seal already sets ENCRYPTED. If we clear it,
            // open's AAD will differ.
            if tampered.header.flags.contains(FcpcFrameFlags::COMPRESSED) {
                tampered.header.flags.remove(FcpcFrameFlags::COMPRESSED);
            } else {
                tampered.header.flags.insert(FcpcFrameFlags::COMPRESSED);
            }
            // If the toggle was a no-op for some reason (impossible
            // here but safe to guard), skip.
            header_changed = tampered.header.flags != frame.header.flags;
        }
    }
    if header_changed {
        match tampered.open(direction, &input.k_ctx) {
            Err(_) => {}
            Ok(_) => panic!(
                "AAD-tampered frame opened (aad_disc={}) — AAD binding broken \
                 for one of (session_id, seq, flags)",
                input.aad_disc % 3
            ),
        }
    }

    // ── PROPERTY 7: ciphertext / tag tamper rejection ─────────────────
    if !frame.ciphertext.is_empty() {
        let mut t = frame.clone();
        if input.tamper_target {
            // Tag tamper.
            let bit = (input.tamper_index as usize) % (t.tag.len() * 8);
            t.tag[bit / 8] ^= 1u8 << (bit % 8);
        } else {
            // Ciphertext tamper.
            let bit = (input.tamper_index as usize) % (t.ciphertext.len() * 8);
            t.ciphertext[bit / 8] ^= 1u8 << (bit % 8);
        }
        match t.open(direction, &input.k_ctx) {
            Err(_) => {}
            Ok(_) => panic!(
                "tampered {} accepted (tamper_index={}); AEAD authentication broken",
                if input.tamper_target {
                    "tag"
                } else {
                    "ciphertext"
                },
                input.tamper_index
            ),
        }
    }

    // ── PROPERTY 8: encode/decode round-trip ──────────────────────────
    let bytes = frame.encode();
    let decoded = FcpcFrame::decode(&bytes).expect("encode→decode round-trip MUST succeed");
    let decoded_open = decoded
        .open(direction, &input.k_ctx)
        .expect("decoded frame MUST open under same direction + key");
    assert_eq!(
        decoded_open, input.plaintext,
        "encode→decode→open lost or altered plaintext"
    );

    // ── PROPERTY 9: check_replay rejects same seq twice ───────────────
    let mut window = ReplayWindow::new(64);
    frame
        .check_replay(&mut window)
        .expect("first check_replay on fresh window MUST succeed");
    if frame.check_replay(&mut window).is_ok() {
        panic!(
            "check_replay accepted the same seq={} twice — replay window not \
             updated; same frame's MAC could pass twice",
            frame.header.seq
        );
    }
});

/// Once-gated regression anchors for the most load-bearing AEAD bindings.
fn assert_fcpc_aead_anchored() {
    let key = [0x42u8; KEY_SIZE];
    let session_id = MeshSessionId([0xAAu8; SESSION_ID_SIZE]);
    let plaintext = b"FCPC anchor payload";

    let frame = FcpcFrame::seal(
        session_id,
        100,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        plaintext,
        &key,
    )
    .expect("anchor seal");

    // Round-trip works.
    let opened = frame
        .open(SessionDirection::InitiatorToResponder, &key)
        .expect("anchor self-open");
    assert_eq!(&opened, plaintext);

    // (a) Direction reflection attack guard.
    match frame.open(SessionDirection::ResponderToInitiator, &key) {
        Err(_) => {}
        Ok(_) => panic!(
            "ANCHOR REGRESSION: I→R-sealed frame opened under R→I — direction \
             byte dropped from nonce (fcpc.rs:186 ChaCha20Nonce::from_counter_directional). \
             Reflection attack surface re-opened: a captured frame from the \
             initiator could be replayed back to the initiator as if from the \
             responder."
        ),
    }

    // (b) Session-id splice.
    let alt_session = MeshSessionId([0xBBu8; SESSION_ID_SIZE]);
    let mut spliced = frame.clone();
    spliced.header.session_id = alt_session;
    match spliced.open(SessionDirection::InitiatorToResponder, &key) {
        Err(_) => {}
        Ok(_) => panic!(
            "ANCHOR REGRESSION: frame sealed under session A opened under \
             session B (same seq, same key) — session_id dropped from AAD \
             (fcpc.rs:313). Cross-session frame splice surface re-opened."
        ),
    }
}
