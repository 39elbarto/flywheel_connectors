#![no_main]

//! Fuzz target for fcp-cbor float-encoding edges NOT covered by
//! `cbor_float_canonical` (which probes NaN/Inf rejection, -0.0
//! normalization, finite round-trip).
//!
//! Properties asserted:
//!
//!   1. **Float ↔ Integer type non-aliasing**: an integer-valued
//!      `Value::Float(n)` (e.g. 1.0, 2.0) MUST canonicalize to bytes
//!      distinct from `Value::Integer(n as i64)`. The CBOR types have
//!      distinct head bytes (0xfb for f64, 0x00-0x1b for unsigned ints).
//!      A regression that introduced "shortest-form" optimisation could
//!      silently alias `Float(1.0)` to `Integer(1)` — content addressing
//!      for any object storing a numeric value type-distinguishable
//!      from its integer counterpart would change.
//!   2. **Bit-level injectivity over finite, non-degenerate f64**: two
//!      finite, non-NaN, non-±0.0 f64 with distinct bit patterns MUST
//!      canonicalize to distinct bytes. A regression that downcast
//!      through a lower-precision intermediate (e.g. f32) would lose
//!      distinguishability between adjacent f64.
//!   3. **Stable encoding length**: every accepted finite f64 produces
//!      exactly 9 canonical bytes (1 head + 8 payload). A regression to
//!      shortest-form encoding (RFC 8949 §4.2.2) would break
//!      content-address stability for any persisted object whose
//!      canonical bytes have already been validated externally.
//!   4. **Subnormal preservation**: f64 subnormals (exponent=0, mantissa≠0)
//!      MUST round-trip through canonical bytes. A regression that
//!      flushed subnormals to zero would silently lose precision for
//!      near-zero values, breaking determinism.
//!
//!   Once-gated regression anchors:
//!     (a) `to_canonical_cbor(&1.0_f64) ≠ to_canonical_cbor(&1_i64)`
//!     (b) accepted f64 always produces exactly 9 bytes
//!     (c) smallest positive subnormal round-trips byte-for-byte

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::{Integer, Value};
use fcp_cbor::to_canonical_cbor;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const F64_CANONICAL_LEN: usize = 9;

static FLOAT_ENCODING_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Reinterpreted as f64 for the injectivity / stable-length probes.
    bits_a: u64,
    bits_b: u64,
    /// Integer counterpart for the type-non-aliasing MR. We look at
    /// integer-valued floats produced by `bits_a as i64 as f64`.
    int_seed: i64,
}

fn is_canonicalizable(f: f64) -> bool {
    f.is_finite() && f != 0.0
}

fuzz_target!(|data: &[u8]| {
    FLOAT_ENCODING_ANCHOR.call_once(assert_float_encoding_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let f_a = f64::from_bits(input.bits_a);
    let f_b = f64::from_bits(input.bits_b);

    // ── PROPERTY 1: float ↔ integer type non-aliasing ──────────────────
    // Pick an integer-valued float we can compare directly with its
    // integer counterpart.
    if let Some(int_repr) = i64_to_exact_f64(input.int_seed) {
        let f_value = Value::Float(int_repr);
        let i_value = Value::Integer(Integer::from(input.int_seed));

        let bytes_f =
            to_canonical_cbor(&f_value).expect("integer-valued finite float MUST canonicalize");
        let bytes_i = to_canonical_cbor(&i_value).expect("Integer MUST canonicalize");
        assert_ne!(
            bytes_f, bytes_i,
            "Value::Float({int_repr}) and Value::Integer({}) produced identical \
             canonical bytes — float→integer type aliasing regression. CBOR head \
             bytes (0xfb vs 0x00-0x1b) MUST be distinct, otherwise content \
             addressing for objects type-distinguishing numeric values would shift.",
            input.int_seed
        );

        // Bonus: round-trip preservation of the type tag. We re-decode
        // the float bytes and assert it still parses as a Float.
        let decoded: Value = ciborium::from_reader(&bytes_f[..])
            .expect("float canonical bytes decode through ciborium");
        assert!(
            matches!(decoded, Value::Float(_)),
            "canonical bytes for Value::Float({int_repr}) decoded as a non-Float \
             ({decoded:?}) — type tag lost during canonicalization"
        );
    }

    // ── PROPERTY 2: bit-level injectivity ──────────────────────────────
    if is_canonicalizable(f_a) && is_canonicalizable(f_b) && f_a.to_bits() != f_b.to_bits() {
        let bytes_a = to_canonical_cbor(&f_a).expect("finite non-zero f64 MUST canonicalize");
        let bytes_b = to_canonical_cbor(&f_b).expect("finite non-zero f64 MUST canonicalize");
        assert_ne!(
            bytes_a, bytes_b,
            "two distinct finite, non-zero f64 (bits=0x{:016x} vs 0x{:016x}) \
             produced identical canonical bytes — encoding is not injective. \
             Implies a precision-losing intermediate downcast.",
            input.bits_a, input.bits_b
        );
    }

    // ── PROPERTY 3: stable encoding length ─────────────────────────────
    if f_a.is_finite() {
        let bytes = to_canonical_cbor(&f_a).expect("finite f64 MUST canonicalize");
        assert_eq!(
            bytes.len(),
            F64_CANONICAL_LEN,
            "f64 (bits=0x{:016x}) canonicalized to {} bytes; expected exactly {} \
             (1 head + 8 payload). A regression to shortest-form encoding (RFC \
             8949 §4.2.2) would break content-address stability across \
             implementations.",
            input.bits_a,
            bytes.len(),
            F64_CANONICAL_LEN
        );
    }

    // ── PROPERTY 4: subnormal preservation ─────────────────────────────
    // A subnormal has exponent bits = 0 and mantissa bits ≠ 0. Build
    // one from the fuzzer's mantissa seed.
    let mantissa = input.bits_a & 0x000F_FFFF_FFFF_FFFF;
    if mantissa != 0 {
        let sub_bits = mantissa; // sign=0, exponent=0, mantissa=non-zero
        let subnormal = f64::from_bits(sub_bits);
        debug_assert!(subnormal.is_finite() && subnormal != 0.0);

        let bytes = to_canonical_cbor(&subnormal).expect("finite subnormal MUST canonicalize");
        let decoded: f64 = ciborium::from_reader(&bytes[..])
            .expect("subnormal canonical bytes round-trip through ciborium");
        assert_eq!(
            decoded.to_bits(),
            sub_bits,
            "subnormal f64 (bits=0x{:016x}) round-tripped to bits=0x{:016x} — \
             precision lost (likely flush-to-zero or denormal handling regression)",
            sub_bits,
            decoded.to_bits()
        );
    }
});

/// Convert an `i64` to the f64 that exactly represents it, or `None` if
/// the value cannot be represented exactly (only relevant for very
/// large magnitudes outside ±2^53).
fn i64_to_exact_f64(n: i64) -> Option<f64> {
    let f = n as f64;
    if (f as i64) == n { Some(f) } else { None }
}

/// Once-gated anchors for the most load-bearing float-encoding edges.
fn assert_float_encoding_anchored() {
    // (a) Float ↔ Integer type non-aliasing for the canonical small
    // integer-valued float 1.0.
    let bytes_f = to_canonical_cbor(&1.0_f64).expect("anchor 1.0 canonicalizes");
    let bytes_i = to_canonical_cbor(&1_i64).expect("anchor 1 canonicalizes");
    assert_ne!(
        bytes_f, bytes_i,
        "ANCHOR REGRESSION: to_canonical_cbor(&1.0_f64) == to_canonical_cbor(&1_i64) \
         — float→integer type aliasing regression. CBOR head bytes for f64 (0xfb) \
         and unsigned int 1 (0x01) MUST differ; content addressing for numeric \
         types depends on this distinction."
    );

    // (b) Stable encoding length: 1.0_f64 produces exactly 9 bytes
    // (head 0xfb + 8-byte IEEE-754 payload).
    assert_eq!(
        bytes_f.len(),
        F64_CANONICAL_LEN,
        "ANCHOR REGRESSION: to_canonical_cbor(&1.0_f64) produced {} bytes; expected \
         {} (1 head + 8 payload). Shortest-form encoding (RFC 8949 §4.2.2) breaks \
         content-address stability across implementations.",
        bytes_f.len(),
        F64_CANONICAL_LEN
    );

    // (c) Smallest positive subnormal round-trip.
    let smallest_subnormal = f64::from_bits(0x0000_0000_0000_0001);
    let bytes = to_canonical_cbor(&smallest_subnormal).expect("anchor subnormal canonicalizes");
    let decoded: f64 =
        ciborium::from_reader(&bytes[..]).expect("anchor subnormal decodes through ciborium");
    assert_eq!(
        decoded.to_bits(),
        smallest_subnormal.to_bits(),
        "ANCHOR REGRESSION: smallest positive subnormal (bits=0x0000_0000_0000_0001) \
         did not round-trip — bits became 0x{:016x}. Subnormals are being flushed \
         to zero somewhere in the canonical pipeline, silently losing precision.",
        decoded.to_bits()
    );
}
