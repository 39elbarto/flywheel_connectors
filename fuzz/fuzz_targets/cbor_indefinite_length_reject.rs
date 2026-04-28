#![no_main]

//! Fuzz target for CBOR indefinite-length wire-form rejection at the
//! canonical-decode boundary.
//!
//! CBOR has indefinite-length encodings (RFC 8949 §3.2):
//!   - 0x9f: indefinite-length array (terminated by 0xff break)
//!   - 0xbf: indefinite-length map (same)
//!   - 0x5f: indefinite-length byte string
//!   - 0x7f: indefinite-length text string
//!
//! Canonical CBOR (§4.2.1) mandates definite-length only. fcp-cbor's
//! `CanonicalSerializer::deserialize` re-encodes the decoded Value via
//! `to_canonical_cbor` (which emits definite-length) and compares to
//! the input bytes — indefinite-length input should therefore fail
//! with `NonCanonicalEncoding`.
//!
//! Existing `dyfmr` (decode_hello_ack_canonical) and `cchj5`
//! (canonical_serializer_schema_binding) cover trailing-bytes and
//! schema-prefix gates but NOT the indefinite-length rejection.
//!
//! A regression that accepted indefinite-length wire forms would let
//! attackers smuggle non-canonical bytes past the canonical-encoding
//! gate, breaking content-address stability across implementations.
//!
//! Properties asserted:
//!
//!   1. **Indefinite array** rejected: `0x9f 0x00 0xff` (indef array
//!      containing integer 0) MUST trip `NonCanonicalEncoding` when
//!      deserialized with the matching schema.
//!   2. **Indefinite map** rejected: `0xbf 0x00 0xf6 0xff` (indef map
//!      with key=0, value=null).
//!   3. **Indefinite byte string** rejected: `0x5f 0x40 0xff` (indef
//!      bytes with one empty chunk).
//!   4. **Indefinite text string** rejected: `0x7f 0x60 0xff` (indef
//!      text with one empty chunk).
//!
//!   Once-gated anchors verify each wire form's exact rejection.
//!   The fuzzed iterations stress with arbitrary inner content.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use fcp_cbor::{CanonicalSerializer, SCHEMA_HASH_LEN, SchemaId, SerializationError};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static INDEFINITE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Discriminator: 0=array, 1=map, 2=bytes, 3=text.
    kind_disc: u8,
    /// Padding bytes (one chunk's content).
    chunk: Vec<u8>,
}

const MAX_CHUNK: usize = 64;

fn schema() -> SchemaId {
    SchemaId::new("fcp.fuzz", "IndefRejection", Version::new(1, 0, 0))
}

fn wrap(cbor_bytes: &[u8]) -> Vec<u8> {
    let s = schema();
    let prefix = s.hash();
    let mut out = Vec::with_capacity(SCHEMA_HASH_LEN + cbor_bytes.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(cbor_bytes);
    out
}

/// Build an indefinite-length CBOR encoding for the given kind.
fn build_indefinite(kind: u8, chunk: &[u8]) -> Vec<u8> {
    match kind % 4 {
        0 => {
            // Indef array: 0x9f || items || 0xff. Use a single integer 0
            // as the only element.
            let mut out = vec![0x9f, 0x00, 0xff];
            // Optionally inject extra inner items from chunk bytes (each
            // u8 → CBOR unsigned int 0..23 directly).
            if !chunk.is_empty() {
                out.clear();
                out.push(0x9f);
                for &b in chunk.iter().take(8) {
                    out.push(b & 0x17); // small unsigned int 0..=23
                }
                out.push(0xff);
            }
            out
        }
        1 => {
            // Indef map: 0xbf || (key, value) pairs || 0xff.
            // One pair: int 0 → null.
            vec![0xbf, 0x00, 0xf6, 0xff]
        }
        2 => {
            // Indef byte string: 0x5f || (definite byte chunks) || 0xff.
            let mut out = vec![0x5f];
            // One empty byte string chunk.
            out.push(0x40);
            out.push(0xff);
            // Or one short chunk from input.
            if !chunk.is_empty() {
                out.clear();
                out.push(0x5f);
                let n = chunk.len().min(8);
                out.push(0x40 | (n as u8)); // bstr head with length n (0..=23)
                out.extend_from_slice(&chunk[..n]);
                out.push(0xff);
            }
            out
        }
        _ => {
            // Indef text string: 0x7f || (definite text chunks) || 0xff.
            // ASCII-only chunk to keep ciborium decode happy.
            let mut out = vec![0x7f, 0x60, 0xff]; // empty chunk
            if !chunk.is_empty() {
                let safe: Vec<u8> = chunk.iter().map(|&b| b & 0x7f).take(8).collect();
                out.clear();
                out.push(0x7f);
                let n = safe.len();
                out.push(0x60 | (n as u8)); // tstr head, length n (0..=23)
                out.extend_from_slice(&safe);
                out.push(0xff);
            }
            out
        }
    }
}

fuzz_target!(|data: &[u8]| {
    INDEFINITE_ANCHOR.call_once(assert_indefinite_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.chunk.len() > MAX_CHUNK {
        return;
    }

    let cbor_bytes = build_indefinite(input.kind_disc, &input.chunk);
    let envelope = wrap(&cbor_bytes);
    let s = schema();

    let result = CanonicalSerializer::deserialize::<Value>(&envelope, &s);

    // ── PROPERTY: indefinite-length wire form rejected ────────────────
    match result {
        Err(SerializationError::NonCanonicalEncoding) => {}
        Err(SerializationError::CborDeserialize(_)) => {
            // ciborium might reject malformed indef bytes earlier; that's
            // also acceptable rejection.
        }
        Err(SerializationError::PayloadTooLarge { .. }) => {}
        Err(SerializationError::TrailingBytes) => {}
        Err(other) => panic!(
            "indefinite-length kind={} returned unexpected error {other:?}",
            input.kind_disc % 4
        ),
        Ok(_) => panic!(
            "indefinite-length wire form (kind={}) accepted by canonical \
             deserialize — non-canonical CBOR can pass the canonical encoding \
             gate; content-address stability across implementations breaks",
            input.kind_disc % 4
        ),
    }
});

/// Once-gated anchors: each canonical indefinite-length wire form
/// MUST be rejected with NonCanonicalEncoding (or another typed error
/// from the cbor family).
fn assert_indefinite_anchored() {
    let s = schema();

    fn assert_rejected(envelope: &[u8], schema: &SchemaId, kind: &str) {
        match CanonicalSerializer::deserialize::<Value>(envelope, schema) {
            Err(SerializationError::NonCanonicalEncoding)
            | Err(SerializationError::CborDeserialize(_))
            | Err(SerializationError::PayloadTooLarge { .. })
            | Err(SerializationError::TrailingBytes) => {}
            Err(other) => panic!("ANCHOR: indef {kind} returned unexpected {other:?}"),
            Ok(_) => panic!(
                "ANCHOR REGRESSION: indefinite-length {kind} accepted — \
                 canonical-encoding rejection at lib.rs:332-334 broken"
            ),
        }
    }

    // Indef array containing integer 0.
    let arr_bytes = vec![0x9f, 0x00, 0xff];
    let env = wrap(&arr_bytes);
    assert_rejected(&env, &s, "array (0x9f ... 0xff)");

    // Indef map { 0: null }.
    let map_bytes = vec![0xbf, 0x00, 0xf6, 0xff];
    let env = wrap(&map_bytes);
    assert_rejected(&env, &s, "map (0xbf ... 0xff)");

    // Indef byte string with empty chunk.
    let bstr_bytes = vec![0x5f, 0x40, 0xff];
    let env = wrap(&bstr_bytes);
    assert_rejected(&env, &s, "byte string (0x5f ... 0xff)");

    // Indef text string with empty chunk.
    let tstr_bytes = vec![0x7f, 0x60, 0xff];
    let env = wrap(&tstr_bytes);
    assert_rejected(&env, &s, "text string (0x7f ... 0xff)");
}
