#![no_main]

//! Fuzz target for `MeshSessionHelloRetry` canonical-CBOR round-trip
//! (session.rs:511-518).
//!
//! `MeshSessionHelloRetry` is the stateless cookie challenge for the
//! hello-retry handshake step. It has 4 fields (from, to, cookie,
//! timestamp) with derived Serialize/Deserialize. NOT fuzzed as a
//! discrete unit.
//!
//! Properties asserted:
//!
//!   1. **Canonical-CBOR round-trip**: encode → decode preserves all
//!      4 fields verbatim.
//!   2. **Re-encoding determinism**: encode(decoded) == encode(original).
//!   3. **JSON serde round-trip** (alternative wire format).
//!
//!   Once-gated anchor: known HelloRetry round-trips byte-for-byte.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::to_canonical_cbor;
use fcp_core::TailscaleNodeId;
use fcp_protocol::{MeshSessionHelloRetry, SessionCookie};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const COOKIE_SIZE: usize = 32;

static HELLO_RETRY_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    cookie: [u8; COOKIE_SIZE],
    timestamp: u64,
    from_disc: u8,
    to_disc: u8,
}

const NODE_IDS: [&str; 4] = ["node-a", "node-b", "node-c", "node-d"];

fn pick_node(disc: u8) -> TailscaleNodeId {
    TailscaleNodeId::new(NODE_IDS[(disc as usize) % NODE_IDS.len()])
}

fuzz_target!(|data: &[u8]| {
    HELLO_RETRY_ANCHOR.call_once(assert_hello_retry_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let retry = MeshSessionHelloRetry {
        from: pick_node(input.from_disc),
        to: pick_node(input.to_disc),
        cookie: SessionCookie(input.cookie),
        timestamp: input.timestamp,
    };

    // ── PROPERTY 1: canonical-CBOR round-trip ─────────────────────────
    let bytes = to_canonical_cbor(&retry).expect("canonical-CBOR encode");
    let decoded: MeshSessionHelloRetry =
        ciborium::from_reader(&bytes[..]).expect("ciborium decode");

    assert_eq!(
        decoded.from.as_str(),
        retry.from.as_str(),
        "from round-trip"
    );
    assert_eq!(decoded.to.as_str(), retry.to.as_str(), "to round-trip");
    assert_eq!(
        decoded.cookie.as_bytes(),
        retry.cookie.as_bytes(),
        "cookie round-trip"
    );
    assert_eq!(decoded.timestamp, retry.timestamp, "timestamp round-trip");

    // ── PROPERTY 2: re-encoding determinism ──────────────────────────
    let bytes2 = to_canonical_cbor(&decoded).expect("re-encode");
    assert_eq!(
        bytes, bytes2,
        "encode(decode(bytes)) != bytes — canonicalization not idempotent for HelloRetry"
    );

    // ── PROPERTY 3: JSON round-trip ──────────────────────────────────
    let json = serde_json::to_string(&retry).expect("JSON encode");
    let from_json: MeshSessionHelloRetry = serde_json::from_str(&json).expect("JSON decode");
    assert_eq!(from_json.from.as_str(), retry.from.as_str());
    assert_eq!(from_json.to.as_str(), retry.to.as_str());
    assert_eq!(from_json.cookie.as_bytes(), retry.cookie.as_bytes());
    assert_eq!(from_json.timestamp, retry.timestamp);
});

/// Once-gated anchor: known HelloRetry round-trips byte-for-byte.
fn assert_hello_retry_anchored() {
    let retry = MeshSessionHelloRetry {
        from: TailscaleNodeId::new("anchor-from"),
        to: TailscaleNodeId::new("anchor-to"),
        cookie: SessionCookie([0xAAu8; COOKIE_SIZE]),
        timestamp: 0x0123_4567_89AB_CDEF,
    };

    let bytes = to_canonical_cbor(&retry).expect("ANCHOR: encode");
    let decoded: MeshSessionHelloRetry = ciborium::from_reader(&bytes[..]).expect("ANCHOR: decode");

    assert_eq!(decoded.from.as_str(), "anchor-from");
    assert_eq!(decoded.to.as_str(), "anchor-to");
    assert_eq!(decoded.cookie.as_bytes(), &[0xAAu8; COOKIE_SIZE]);
    assert_eq!(decoded.timestamp, 0x0123_4567_89AB_CDEF);

    // Re-encode is byte-stable.
    let bytes2 = to_canonical_cbor(&decoded).expect("ANCHOR: re-encode");
    assert_eq!(
        bytes, bytes2,
        "ANCHOR REGRESSION: known HelloRetry did not encode → decode → re-encode \
         byte-for-byte"
    );
}
