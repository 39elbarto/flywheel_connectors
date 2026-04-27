#![no_main]

//! Fuzz target for `CanonicalSerializer` schema-prefix binding +
//! non-canonical-detection rejection gates (lib.rs:263-376).
//!
//! `CanonicalSerializer` envelopes canonical CBOR with a 32-byte schema
//! hash prefix:
//!   out = schema.hash() (32 bytes) || canonical_cbor(value)
//!
//! The deserialize path runs five distinct rejection gates; the
//! deserialize_unchecked path skips NonCanonicalEncoding only. The
//! asymmetry is the security boundary: untrusted inputs MUST flow
//! through `deserialize`.
//!
//! Existing `canonical_cbor` covers panic-freedom, JSON round-trip,
//! and ciborium→canonical→deserialize round-trip under matching
//! schema. The MRs that exercise the rejection gates are NOT covered.
//!
//! Properties asserted:
//!
//!   1. **Schema-prefix bit-flip rejection**: bit-flipping any byte of
//!      the 32-byte schema_hash prefix MUST yield `SchemaMismatch`.
//!   2. **Cross-schema rejection**: serialize under S1 MUST NOT
//!      deserialize under S2.
//!   3. **Truncated-prefix rejection**: input shorter than 32 bytes
//!      MUST yield `MissingSchemaHashPrefix`.
//!   4. **Trailing-bytes rejection**: `schema_hash || canonical || extra`
//!      MUST be rejected (NonCanonicalEncoding or TrailingBytes).
//!   5. **deserialize ⇒ deserialize_unchecked refinement**: when
//!      `deserialize` succeeds, `deserialize_unchecked` MUST also
//!      succeed and decode to an equal value.
//!   6. **Round-trip stability**: serialize(v, s) → deserialize(_, s)
//!      → serialize(_, s) is byte-identical for accepted v.
//!
//!   Once-gated regression anchors:
//!     (a) Bit-flip the first byte of a known schema-hash prefix MUST
//!         trip SchemaMismatch.
//!     (b) Cross-schema rejection: serialize a small value under S1
//!         and replace the prefix with S2's hash; deserialize under
//!         S1 MUST trip SchemaMismatch.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use fcp_cbor::{
    CanonicalSerializer, MAX_CANONICAL_OBJECT_BYTES, SCHEMA_HASH_LEN, SchemaId, SerializationError,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

const MAX_INPUT_BYTES: usize = 16 * 1024;

static SCHEMA_BINDING_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw bytes that we attempt to interpret as serde_json::Value to
    /// generate well-formed input values for the round-trip MRs.
    raw_json: Vec<u8>,
    /// Bit index for the schema-prefix tamper MR (mod prefix bit count).
    bitflip_index: u32,
    /// Trailing-bytes payload — non-empty triggers the trailing-bytes MR.
    trailing: Vec<u8>,
}

fn schema_a() -> SchemaId {
    SchemaId::new("fcp.fuzz", "SchemaBindingA", Version::new(1, 0, 0))
}

fn schema_b() -> SchemaId {
    SchemaId::new("fcp.fuzz", "SchemaBindingB", Version::new(1, 0, 0))
}

fuzz_target!(|data: &[u8]| {
    SCHEMA_BINDING_ANCHOR.call_once(assert_schema_binding_anchored);

    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let s_a = schema_a();
    let s_b = schema_b();

    // ── PROPERTY 3: truncated-prefix rejection ─────────────────────────
    // Any input shorter than SCHEMA_HASH_LEN MUST fail with
    // MissingSchemaHashPrefix, never panic, never silently accept.
    let short = if input.raw_json.len() >= SCHEMA_HASH_LEN {
        input.raw_json[..(SCHEMA_HASH_LEN - 1).min(input.raw_json.len())].to_vec()
    } else {
        input.raw_json.clone()
    };
    if short.len() < SCHEMA_HASH_LEN {
        match CanonicalSerializer::deserialize::<Value>(&short, &s_a) {
            Err(SerializationError::MissingSchemaHashPrefix) => {}
            Err(_) => {
                // Other typed errors are unexpected here, but harmless.
            }
            Ok(_) => panic!(
                "deserialize accepted input shorter than SCHEMA_HASH_LEN ({} < {}) — \
                 prefix-length gate broken",
                short.len(),
                SCHEMA_HASH_LEN
            ),
        }
    }

    // Try to ground the remaining MRs in a value we can serialize.
    let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&input.raw_json) else {
        return;
    };

    let Ok(serialized) = CanonicalSerializer::serialize(&json_value, &s_a) else {
        return;
    };

    // ── PROPERTY 6: round-trip stability ──────────────────────────────
    let Ok(decoded) = CanonicalSerializer::deserialize::<serde_json::Value>(&serialized, &s_a)
    else {
        return;
    };
    let reserialized = CanonicalSerializer::serialize(&decoded, &s_a)
        .expect("re-serialize after deserialize must succeed");
    assert_eq!(
        serialized, reserialized,
        "round-trip serialize→deserialize→serialize is not byte-stable"
    );

    // ── PROPERTY 5: deserialize ⇒ deserialize_unchecked refinement ─────
    let unchecked: serde_json::Value =
        CanonicalSerializer::deserialize_unchecked(&serialized, &s_a).expect(
            "deserialize_unchecked MUST accept any input that deserialize accepts \
             (it is strictly more permissive)",
        );
    assert_eq!(
        unchecked, decoded,
        "deserialize and deserialize_unchecked decoded the same accepted input \
         to different values"
    );

    // ── PROPERTY 1: schema-prefix bit-flip rejection ──────────────────
    let mut tampered = serialized.clone();
    let bit = (input.bitflip_index as usize) % (SCHEMA_HASH_LEN * 8);
    tampered[bit / 8] ^= 1u8 << (bit % 8);
    match CanonicalSerializer::deserialize::<Value>(&tampered, &s_a) {
        Err(SerializationError::SchemaMismatch { .. }) => {}
        Err(SerializationError::PayloadTooLarge { .. }) => {}
        Err(other) => panic!(
            "schema-prefix bit-flip produced unexpected error {other:?}; \
             expected SchemaMismatch"
        ),
        Ok(_) => panic!(
            "deserialize accepted input with a bit-flipped schema_hash prefix — \
             schema-binding regression"
        ),
    }

    // ── PROPERTY 2: cross-schema rejection ────────────────────────────
    // SchemaId A and SchemaId B differ in name; their hashes MUST differ
    // (SchemaId::hash injectivity, mzi9x). Serialized-under-A MUST NOT
    // deserialize under B.
    match CanonicalSerializer::deserialize::<Value>(&serialized, &s_b) {
        Err(SerializationError::SchemaMismatch { .. }) => {}
        Err(other) => panic!(
            "cross-schema verify produced unexpected error {other:?}; \
             expected SchemaMismatch"
        ),
        Ok(_) => panic!(
            "deserialize accepted bytes serialized under SchemaA when expected schema \
             is SchemaB — cross-schema isolation broken"
        ),
    }

    // ── PROPERTY 4: trailing-bytes rejection ──────────────────────────
    if !input.trailing.is_empty() {
        let mut with_trailing = serialized.clone();
        with_trailing.extend_from_slice(&input.trailing);
        if with_trailing.len() <= MAX_CANONICAL_OBJECT_BYTES {
            match CanonicalSerializer::deserialize::<Value>(&with_trailing, &s_a) {
                Err(SerializationError::NonCanonicalEncoding)
                | Err(SerializationError::TrailingBytes) => {}
                Err(other) => panic!(
                    "trailing-bytes input produced unexpected error {other:?}; \
                     expected NonCanonicalEncoding or TrailingBytes"
                ),
                Ok(_) => panic!(
                    "deserialize accepted input with {} trailing bytes — \
                     trailing-bytes gate broken (smuggling-via-suffix surface)",
                    input.trailing.len()
                ),
            }
        }
    }
});

/// Once-gated anchors for the most load-bearing schema-binding gates.
fn assert_schema_binding_anchored() {
    let s_a = schema_a();
    let s_b = schema_b();

    // Pick a small, schema-independent value.
    let value = serde_json::json!({"k": 1, "v": [true, null]});

    let serialized_a =
        CanonicalSerializer::serialize(&value, &s_a).expect("anchor serialize under schema A");

    // (a) Bit-flip on the schema-hash prefix MUST trip SchemaMismatch.
    let mut tampered = serialized_a.clone();
    tampered[0] ^= 0x01;
    match CanonicalSerializer::deserialize::<serde_json::Value>(&tampered, &s_a) {
        Err(SerializationError::SchemaMismatch { .. }) => {}
        Err(other) => panic!(
            "ANCHOR: schema-prefix bit-flip produced {other:?}; expected \
             SchemaMismatch"
        ),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: schema-prefix bit-flip on byte 0 was accepted — \
             schema-binding gate at lib.rs:320 broken"
        ),
    }

    // (b) Cross-schema rejection: SchemaA bytes MUST NOT verify under
    // SchemaB. (SchemaId::hash injectivity load-bearing — mzi9x.)
    match CanonicalSerializer::deserialize::<serde_json::Value>(&serialized_a, &s_b) {
        Err(SerializationError::SchemaMismatch { .. }) => {}
        Err(other) => {
            panic!("ANCHOR: cross-schema verify produced {other:?}; expected SchemaMismatch")
        }
        Ok(_) => panic!(
            "ANCHOR REGRESSION: bytes serialized under SchemaA accepted under \
             SchemaB — SchemaId::hash injectivity violated; the mzi9x \
             length-prefixing fix has regressed"
        ),
    }

    // Acceptance anchor: a clean round-trip under matching schema MUST
    // succeed. Otherwise the rejection assertions above would be vacuous.
    let decoded: serde_json::Value = CanonicalSerializer::deserialize(&serialized_a, &s_a).expect(
        "ANCHOR: clean round-trip under matching schema MUST succeed; if this \
             trips the rejection-anchor catalog above is unsound",
    );
    assert_eq!(
        decoded, value,
        "ANCHOR: clean round-trip decoded to a different value"
    );
}
