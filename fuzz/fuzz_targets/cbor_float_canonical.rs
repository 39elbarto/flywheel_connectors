#![no_main]

//! Fuzz target for fcp-cbor float canonicalization rules.
//!
//! `canonicalize_value_in_place` (lib.rs:492-499) enforces three rules
//! on every `Value::Float` in the canonicalization tree:
//!
//!   (a) NaN  → `SerializationError::NonFiniteFloat`
//!   (b) ±Inf → `SerializationError::NonFiniteFloat`
//!   (c) -0.0 → normalized to +0.0 before encoding
//!
//! The existing `fuzz_canonicalize_map_deterministic` target explicitly
//! substitutes `0.0` for NaN inputs (the `arbitrary_leaf` branch), so
//! the rejection path for non-finite floats is **never exercised** by
//! existing fuzz coverage. A regression that dropped the rejection
//! (e.g., a refactor that moved the check past the encode boundary)
//! would let an attacker smuggle distinct NaN bit patterns through the
//! canonical-CBOR boundary, breaking content-addressing determinism
//! (every NaN payload encodes as a *different* 8-byte sequence under
//! ciborium's IEEE-754 round-trip).
//!
//! Properties asserted:
//!
//!   1. `to_canonical_cbor::<f64>` is panic-free over every 64-bit bit
//!      pattern (whether it represents NaN, ±Inf, subnormal, or finite).
//!   2. NaN bit patterns (sign × signaling × payload) MUST yield
//!      `SerializationError::NonFiniteFloat`.
//!   3. ±Infinity MUST yield `NonFiniteFloat`.
//!   4. **Negative zero canonicalization**: `to_canonical_cbor(-0.0)`
//!      MUST byte-equal `to_canonical_cbor(0.0)` — the public-facing
//!      property that downstream content-addressing relies on.
//!   5. Every accepted (finite) float round-trips through
//!      `ciborium::from_reader::<f64, _>` to a value that re-encodes to
//!      the same bytes.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use fcp_cbor::{SerializationError, to_canonical_cbor};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static NEG_ZERO_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Reinterpreted as f64 to reach every IEEE-754 bit pattern,
    /// including NaN payloads ciborium otherwise can't round-trip.
    bits: u64,
}

fuzz_target!(|data: &[u8]| {
    NEG_ZERO_ANCHOR.call_once(assert_neg_zero_canonicalizes);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let f = f64::from_bits(input.bits);

    // ── PROPERTY 1: to_canonical_cbor is total over all f64 patterns ──
    let result = to_canonical_cbor(&f);

    if f.is_nan() || f.is_infinite() {
        // ── PROPERTY 2 + 3: NaN / Infinity rejection ──────────────────
        match result {
            Err(SerializationError::NonFiniteFloat) => {}
            Err(other) => panic!(
                "non-finite f64 (bits=0x{:016x}) MUST trip NonFiniteFloat, \
                 not {other:?}",
                input.bits
            ),
            Ok(_) => panic!(
                "non-finite f64 (bits=0x{:016x}, is_nan={}, is_inf={}) was \
                 accepted by canonicalization",
                input.bits,
                f.is_nan(),
                f.is_infinite()
            ),
        }
        return;
    }

    // ── PROPERTY 5: finite round-trip ──────────────────────────────────
    let bytes = result.expect("finite f64 MUST canonicalize without error");

    // Decode and re-encode; byte equality is what downstream content
    // addressing relies on.
    let Ok(decoded) = ciborium::from_reader::<Value, _>(&bytes[..]) else {
        panic!(
            "canonical bytes for finite f64 (bits=0x{:016x}) failed to \
             round-trip through ciborium decoder",
            input.bits
        );
    };

    let recanonical =
        to_canonical_cbor(&decoded).expect("decoded value of canonical bytes must re-encode");
    assert_eq!(
        bytes, recanonical,
        "encode → decode → encode produced different bytes for f64 \
         (bits=0x{:016x})",
        input.bits
    );

    // ── PROPERTY 4 (subset): negative-zero specifically ─────────────────
    // If the input was -0.0, the canonical bytes must equal +0.0's
    // canonical bytes — the lib.rs:496-498 normalization rule.
    if input.bits == (-0.0_f64).to_bits() {
        let pos_zero_bytes = to_canonical_cbor(&0.0_f64).expect("0.0 canonicalizes");
        assert_eq!(
            bytes, pos_zero_bytes,
            "-0.0 canonical bytes diverged from +0.0 — content-addressing \
             would assign distinct ObjectIds to logically equal payloads"
        );
    }
});

/// Hand-crafted regression anchor. Run once per process so we always
/// catch a regression that drops the negative-zero normalization.
/// Constructed inputs (rather than fuzzer-discovered) because the
/// fuzzer would only hit the exact 0x8000_0000_0000_0000 pattern by
/// chance.
fn assert_neg_zero_canonicalizes() {
    let neg_zero = -0.0_f64;
    let pos_zero = 0.0_f64;
    assert_eq!(
        neg_zero.to_bits(),
        0x8000_0000_0000_0000,
        "f64 sanity: -0.0 bit pattern shifted under us"
    );
    assert_ne!(
        neg_zero.to_bits(),
        pos_zero.to_bits(),
        "f64 sanity: -0.0 and 0.0 must differ at the bit level"
    );

    let nz_bytes = to_canonical_cbor(&neg_zero).expect("-0.0 canonicalizes (lib.rs:496-498)");
    let pz_bytes = to_canonical_cbor(&pos_zero).expect("0.0 canonicalizes");
    assert_eq!(
        nz_bytes, pz_bytes,
        "negative-zero normalization regression: encode(-0.0) ≠ encode(0.0). \
         Content-addressed objects whose only difference is the sign bit on \
         a zero value would now hash to different ObjectIds"
    );

    // Also anchor that NaN explicitly trips the rejection — guards
    // against a refactor that drops the is_nan branch.
    let nan = f64::from_bits(0x7ff8_0000_0000_0001);
    assert!(
        matches!(
            to_canonical_cbor(&nan),
            Err(SerializationError::NonFiniteFloat)
        ),
        "canonical NaN payload must trip NonFiniteFloat (lib.rs:493-494)"
    );

    // And the +Inf rejection.
    assert!(
        matches!(
            to_canonical_cbor(&f64::INFINITY),
            Err(SerializationError::NonFiniteFloat)
        ),
        "+Infinity must trip NonFiniteFloat"
    );
}
