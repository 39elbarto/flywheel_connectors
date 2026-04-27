#![no_main]

//! Metamorphic-relations fuzz target for fcp-protocol session-handshake
//! primitives.
//!
//! Existing `fuzz_session` and `fuzz_session_transcript` cover decoders
//! and discard accepted structures.  The handshake's *invariant*
//! relations — what the responder-picks rule actually means, what
//! binds a session MAC to a particular (key, session, direction, seq,
//! frame) tuple — are not yet asserted across an arbitrary input
//! space.  This target fills that gap.
//!
//! Metamorphic relations:
//!
//!   MR-NEG-1 (idempotence): `negotiate_suite` is a pure function;
//!     two calls on the same inputs return the same output.
//!
//!   MR-NEG-2 (initiator-shuffle invariance): the responder-picks
//!     rule is independent of the initiator's order — shuffling
//!     `initiator_suites` MUST NOT change the result.
//!
//!   MR-NEG-3 (containment + floor): if `negotiate_suite` returns
//!     `Some(s)`, then `s` is in BOTH suite lists and at or above
//!     `MINIMUM_SUITE`.
//!
//!   MR-NEG-4 (responder-priority): if `negotiate_suite` returns
//!     `Some(s)`, then `s` is the FIRST element of `responder_suites`
//!     that satisfies the containment + floor predicate.  Equivalently:
//!     no earlier responder suite is present in the initiator list and
//!     at-or-above the floor.
//!
//!   MR-NEG-5 (no-overlap → None): if `initiator_suites` and
//!     `responder_suites` have empty intersection, the result is None.
//!
//!   MR-MAC-1 (round-trip): `verify_session_mac` accepts the output of
//!     `compute_session_mac` for any matching (suite, key, session,
//!     direction, seq, frame).
//!
//!   MR-MAC-2..6 (binding): mutating any of `mac_key`, `session_id`,
//!     `direction`, `seq`, or `frame_bytes` MUST cause verification to
//!     reject.  These are the "what does this MAC bind to" guarantees
//!     the protocol relies on for replay defense (seq), reflection
//!     defense (direction), and key isolation (mac_key + session_id).

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{
    MINIMUM_SUITE, MeshSessionId, SessionCryptoSuite, SessionDirection, compute_session_mac,
    negotiate_suite, verify_session_mac,
};
use libfuzzer_sys::fuzz_target;

const MAX_SUITES_PER_LIST: usize = 8;
const MAX_FRAME_BYTES: usize = 4 * 1024;
const SESSION_ID_SIZE: usize = 16;

#[derive(Arbitrary, Debug)]
struct Input {
    initiator_seed: Vec<u8>,
    responder_seed: Vec<u8>,
    permute_seed: u64,

    suite_id: u8,
    mac_key: [u8; 32],
    session_id_bytes: [u8; SESSION_ID_SIZE],
    direction_bit: bool,
    seq: u64,
    frame_bytes: Vec<u8>,

    // Mutation parameters (which field to perturb for the binding tests).
    bitflip_index: u32,
}

/// Build a suite list from arbitrary bytes — each byte maps onto a
/// suite identifier (with an unknown-id branch returning early). The
/// length is capped so the responder-priority MR stays linear.
fn suites_from(bytes: &[u8]) -> Vec<SessionCryptoSuite> {
    bytes
        .iter()
        .take(MAX_SUITES_PER_LIST)
        .filter_map(|b| match b % 4 {
            // Bias toward Suite1 / Suite2; the other branches keep the
            // distribution from collapsing to "always full lists" so we
            // also explore short / empty lists.
            0 => Some(SessionCryptoSuite::Suite1),
            1 => Some(SessionCryptoSuite::Suite2),
            _ => None,
        })
        .collect()
}

fn pick_suite(id: u8) -> SessionCryptoSuite {
    if id.is_multiple_of(2) {
        SessionCryptoSuite::Suite1
    } else {
        SessionCryptoSuite::Suite2
    }
}

fn pick_direction(bit: bool) -> SessionDirection {
    if bit {
        SessionDirection::InitiatorToResponder
    } else {
        SessionDirection::ResponderToInitiator
    }
}

fn flip_direction(d: SessionDirection) -> SessionDirection {
    match d {
        SessionDirection::InitiatorToResponder => SessionDirection::ResponderToInitiator,
        SessionDirection::ResponderToInitiator => SessionDirection::InitiatorToResponder,
    }
}

fn suite_rank(s: SessionCryptoSuite) -> u8 {
    // Mirror the private suite_rank in fcp-protocol. The MR layer is
    // the public contract: rank monotone with id is the published
    // invariant.
    match s {
        SessionCryptoSuite::Suite1 => 1,
        SessionCryptoSuite::Suite2 => 2,
    }
}

/// Cheap deterministic shuffle (Fisher-Yates with xorshift64*).
fn shuffle<T: Clone>(items: &[T], mut state: u64) -> Vec<T> {
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }
    let mut v = items.to_vec();
    for i in (1..v.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) as usize) % (i + 1);
        v.swap(i, j);
    }
    v
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

    let initiator_suites = suites_from(&input.initiator_seed);
    let responder_suites = suites_from(&input.responder_seed);
    let floor = suite_rank(MINIMUM_SUITE);

    let result = negotiate_suite(&initiator_suites, &responder_suites);

    // ── MR-NEG-1: idempotence ───────────────────────────────────────────
    assert_eq!(
        result,
        negotiate_suite(&initiator_suites, &responder_suites),
        "negotiate_suite is not idempotent"
    );

    // ── MR-NEG-2: initiator-shuffle invariance ──────────────────────────
    let shuffled_initiator = shuffle(&initiator_suites, input.permute_seed);
    assert_eq!(
        result,
        negotiate_suite(&shuffled_initiator, &responder_suites),
        "negotiate_suite changed when initiator list was reordered (responder-picks violated)"
    );

    // ── MR-NEG-3 + MR-NEG-4: containment, floor, responder-priority ────
    if let Some(s) = result {
        assert!(
            initiator_suites.contains(&s),
            "negotiated suite {s:?} not in initiator list"
        );
        assert!(
            responder_suites.contains(&s),
            "negotiated suite {s:?} not in responder list"
        );
        assert!(
            suite_rank(s) >= floor,
            "negotiated suite {s:?} below MINIMUM_SUITE floor"
        );

        // Responder-priority: every responder suite preceding `s` in
        // the responder's order must fail the predicate (either not in
        // initiator's list, or below the floor).
        for earlier in responder_suites.iter().take_while(|&&x| x != s) {
            let predicate = initiator_suites.contains(earlier) && suite_rank(*earlier) >= floor;
            assert!(
                !predicate,
                "negotiated {s:?} but earlier responder suite {earlier:?} also satisfies predicate",
            );
        }
    } else {
        // ── MR-NEG-5: None ⇒ no responder suite satisfies predicate ─────
        for r in &responder_suites {
            let predicate = initiator_suites.contains(r) && suite_rank(*r) >= floor;
            assert!(
                !predicate,
                "negotiate_suite returned None but {r:?} satisfies predicate",
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // MAC binding metamorphic relations
    // ──────────────────────────────────────────────────────────────────────

    let suite = pick_suite(input.suite_id);
    let session_id = MeshSessionId(input.session_id_bytes);
    let direction = pick_direction(input.direction_bit);
    let frame_bytes: &[u8] = if input.frame_bytes.len() > MAX_FRAME_BYTES {
        &input.frame_bytes[..MAX_FRAME_BYTES]
    } else {
        &input.frame_bytes[..]
    };

    let Ok(mac) = compute_session_mac(
        suite,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        frame_bytes,
    ) else {
        return;
    };

    // ── MR-MAC-1: round-trip ────────────────────────────────────────────
    verify_session_mac(
        suite,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        frame_bytes,
        &mac,
    )
    .expect("compute_session_mac → verify_session_mac MUST round-trip with matching params");

    // ── MR-MAC-2: mac_key binding ──────────────────────────────────────
    {
        let mut mutated_key = input.mac_key;
        let bit = (input.bitflip_index as usize) % (mutated_key.len() * 8);
        flip_bit(&mut mutated_key, bit);
        if mutated_key != input.mac_key {
            assert!(
                verify_session_mac(
                    suite,
                    &mutated_key,
                    &session_id,
                    direction,
                    input.seq,
                    frame_bytes,
                    &mac,
                )
                .is_err(),
                "verify_session_mac accepted a flipped mac_key bit (MAC not bound to key)",
            );
        }
    }

    // ── MR-MAC-3: session_id binding ───────────────────────────────────
    {
        let mut mutated_sid = input.session_id_bytes;
        let bit = (input.bitflip_index as usize) % (mutated_sid.len() * 8);
        flip_bit(&mut mutated_sid, bit);
        if mutated_sid != input.session_id_bytes {
            assert!(
                verify_session_mac(
                    suite,
                    &input.mac_key,
                    &MeshSessionId(mutated_sid),
                    direction,
                    input.seq,
                    frame_bytes,
                    &mac,
                )
                .is_err(),
                "verify_session_mac accepted a flipped session_id bit (cross-session replay surface)",
            );
        }
    }

    // ── MR-MAC-4: direction binding (reflection defense) ───────────────
    {
        let flipped = flip_direction(direction);
        assert!(
            verify_session_mac(
                suite,
                &input.mac_key,
                &session_id,
                flipped,
                input.seq,
                frame_bytes,
                &mac,
            )
            .is_err(),
            "verify_session_mac accepted reflected MAC under flipped direction (reflection-attack surface)",
        );
    }

    // ── MR-MAC-5: seq binding (replay defense) ─────────────────────────
    {
        let altered_seq = input.seq.wrapping_add(1);
        if altered_seq != input.seq {
            assert!(
                verify_session_mac(
                    suite,
                    &input.mac_key,
                    &session_id,
                    direction,
                    altered_seq,
                    frame_bytes,
                    &mac,
                )
                .is_err(),
                "verify_session_mac accepted seq+1 under same MAC (replay-attack surface)",
            );
        }
    }

    // ── MR-MAC-6: frame binding ─────────────────────────────────────────
    if !frame_bytes.is_empty() {
        let mut mutated_frame = frame_bytes.to_vec();
        let bit = (input.bitflip_index as usize) % (mutated_frame.len() * 8);
        flip_bit(&mut mutated_frame, bit);
        if mutated_frame != frame_bytes {
            assert!(
                verify_session_mac(
                    suite,
                    &input.mac_key,
                    &session_id,
                    direction,
                    input.seq,
                    &mutated_frame,
                    &mac,
                )
                .is_err(),
                "verify_session_mac accepted mutated frame bytes (MAC not bound to payload)",
            );
        }
    }
});
