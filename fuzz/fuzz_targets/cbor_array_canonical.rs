#![no_main]

//! Metamorphic fuzz target for the `Value::Array` branch of
//! `canonicalize_value_in_place` (lib.rs:484-513).
//!
//! `canonicalize_value_in_place` recursively descends the Value tree;
//! the Array branch (lib.rs:502-506) is positionally distinct from Map
//! (arrays preserve insertion order) and dispatches the same recursive
//! canonicalization to every element. The Map branch is fuzz-covered
//! by `canonicalize_map_deterministic` and `cbor_map_canonical_relations`;
//! the Array branch is not.
//!
//! Properties a regression in the Array branch would silently break:
//!
//!   1. **Order preservation**: `Array([a,b,c])` MUST canonicalize to
//!      bytes that differ from `Array([c,b,a])` when `a ≠ c`. A bug that
//!      sorted array elements would pass the map suite but break interop
//!      and content-addressing for arrays.
//!   2. **Recursive NaN rejection**: an array containing a NaN float
//!      MUST trip `NonFiniteFloat`. A regression that skipped recursion
//!      into Array elements would let a NaN smuggled inside an array
//!      bypass the float canonicalization gate.
//!   3. **Recursive -0.0 normalization**: -0.0 inside an array MUST
//!      canonicalize identically to +0.0 in the same position.
//!   4. **Recursive map-inside-array canonicalization**: a nested map
//!      inside an array MUST still get its keys sorted/deduped.
//!   5. **Depth counting includes array nesting**: arrays nested past
//!      `MAX_CANONICALIZATION_DEPTH` MUST trip `DepthExceeded` — a
//!      regression that incremented depth only on Map would let an
//!      attacker mount a stack-exhaustion DoS via deeply-nested arrays.
//!
//!   Once-gated regression anchors:
//!     (a) Order preservation: hand-constructed [1,2,3] vs [3,2,1] MUST
//!         produce different canonical bytes.
//!     (b) NaN smuggling: an array containing a NaN MUST trip
//!         NonFiniteFloat.
//!     (c) Depth: an array nested 200 levels MUST trip DepthExceeded.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::{Integer, Value};
use fcp_cbor::{
    MAX_CANONICAL_OBJECT_BYTES, MAX_CANONICALIZATION_DEPTH, SerializationError, to_canonical_cbor,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ELEMS: usize = 32;

static ARRAY_REGRESSION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Up to MAX_ELEMS leaf values; we drive structure-aware generation
    /// from this seed bytes payload.
    raw: Vec<u8>,
    /// Whether to swap a single element with -0.0 to exercise the
    /// recursive zero-normalization MR.
    inject_neg_zero: bool,
    /// Index for the neg-zero injection (mod array length).
    neg_zero_idx: u8,
    /// Whether to embed a small map inside the array to exercise the
    /// nested-map canonicalization MR.
    embed_map: bool,
}

fn arbitrary_leaf(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    match u.int_in_range::<u8>(0..=5)? {
        0 => Ok(Value::Integer(Integer::from(u.arbitrary::<i64>()?))),
        1 => {
            let len = u.int_in_range::<usize>(0..=24)?;
            Ok(Value::Bytes(u.bytes(len)?.to_vec()))
        }
        2 => {
            let len = u.int_in_range::<usize>(0..=24)?;
            Ok(Value::Text(
                String::from_utf8_lossy(u.bytes(len)?).into_owned(),
            ))
        }
        3 => Ok(Value::Bool(u.arbitrary::<bool>()?)),
        4 => Ok(Value::Null),
        _ => {
            // Avoid NaN/Inf at the value root — we anchor those once-gated
            // and exercise the MR explicitly via inject_neg_zero. Random
            // float here MUST be finite or the iteration becomes a NaN
            // probe, which is the cbor_float_canonical target's surface.
            let f = u.arbitrary::<f64>()?;
            Ok(Value::Float(if f.is_finite() { f } else { 0.0 }))
        }
    }
}

fn build_array(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Value>> {
    let n = u.int_in_range::<usize>(0..=MAX_ELEMS)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(arbitrary_leaf(u)?);
    }
    Ok(out)
}

fuzz_target!(|data: &[u8]| {
    ARRAY_REGRESSION_ANCHOR.call_once(assert_array_regression_anchored);

    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    let mut u = Unstructured::new(&input.raw);

    let Ok(elements) = build_array(&mut u) else {
        return;
    };
    if elements.is_empty() {
        return;
    }

    let arr = Value::Array(elements.clone());

    // ── PROPERTY 1: order preservation ─────────────────────────────────
    // Reverse the array; if the elements aren't all equal, canonical
    // bytes MUST differ.
    if elements.len() >= 2 && !all_equal_under_canonical(&elements) {
        let mut reversed = elements.clone();
        reversed.reverse();
        let arr_rev = Value::Array(reversed);

        let Ok(bytes_orig) = to_canonical_cbor(&arr) else {
            return;
        };
        let Ok(bytes_rev) = to_canonical_cbor(&arr_rev) else {
            return;
        };
        assert_ne!(
            bytes_orig, bytes_rev,
            "Value::Array of distinct elements canonicalizes to identical bytes \
             when reversed — order preservation broken (the Array branch is \
             behaving like the Map branch's sort path)"
        );
    }

    // ── PROPERTY 3: recursive -0.0 normalization ──────────────────────
    if input.inject_neg_zero {
        let idx = (input.neg_zero_idx as usize) % elements.len();
        let mut with_neg_zero = elements.clone();
        let mut with_pos_zero = elements.clone();
        with_neg_zero[idx] = Value::Float(-0.0_f64);
        with_pos_zero[idx] = Value::Float(0.0_f64);

        let bytes_neg = to_canonical_cbor(&Value::Array(with_neg_zero))
            .expect("array with -0.0 element MUST canonicalize (normalized to +0.0)");
        let bytes_pos = to_canonical_cbor(&Value::Array(with_pos_zero))
            .expect("array with +0.0 element MUST canonicalize");
        assert_eq!(
            bytes_neg, bytes_pos,
            "Value::Array with -0.0 at index {idx} produced different bytes than \
             the same array with +0.0 — recursive zero-normalization broken at \
             lib.rs:496-498 (the Array branch is not feeding floats through \
             canonicalize_value_in_place)"
        );
    }

    // ── PROPERTY 4: recursive map-inside-array canonicalization ────────
    if input.embed_map {
        // Build the same logical map twice: once with keys in order
        // (1,2,3), once reversed (3,2,1). Both wrapped in an array. The
        // canonical bytes MUST be byte-identical because the Map branch
        // sorts; if they differ, the Map branch was skipped during the
        // Array recursion.
        let map_in_order = Value::Map(vec![
            (Value::Integer(Integer::from(1)), Value::Bool(true)),
            (Value::Integer(Integer::from(2)), Value::Bool(false)),
            (Value::Integer(Integer::from(3)), Value::Null),
        ]);
        let map_reversed = Value::Map(vec![
            (Value::Integer(Integer::from(3)), Value::Null),
            (Value::Integer(Integer::from(2)), Value::Bool(false)),
            (Value::Integer(Integer::from(1)), Value::Bool(true)),
        ]);

        let arr_a = Value::Array(vec![map_in_order]);
        let arr_b = Value::Array(vec![map_reversed]);
        let bytes_a = to_canonical_cbor(&arr_a).expect("array of map canonicalizes");
        let bytes_b = to_canonical_cbor(&arr_b).expect("array of reversed-input-map canonicalizes");
        assert_eq!(
            bytes_a, bytes_b,
            "[map(1,2,3)] and [map(3,2,1)] produced different canonical bytes — \
             nested map sort skipped during Array recursion (lib.rs:502-506 \
             dispatching to the wrong canonicalizer)"
        );
    }
});

/// Determine whether all elements canonicalize to the same bytes — used to
/// skip Property 1 when the array is degenerate (all-equal under
/// canonical encoding, where reversal is a no-op).
fn all_equal_under_canonical(elements: &[Value]) -> bool {
    if elements.is_empty() {
        return true;
    }
    let Ok(first) = to_canonical_cbor(&elements[0]) else {
        return false;
    };
    elements.iter().skip(1).all(|e| match to_canonical_cbor(e) {
        Ok(bytes) => bytes == first,
        Err(_) => false,
    })
}

/// Once-gated regression anchors for the most load-bearing Array
/// branch invariants. Run once per process so a regression that drops
/// any of the three trips on every fuzz invocation, not only on
/// fuzzer-discovered inputs.
fn assert_array_regression_anchored() {
    // (a) Order preservation: [1,2,3] vs [3,2,1] MUST produce different
    // bytes.
    let a = Value::Array(vec![
        Value::Integer(Integer::from(1)),
        Value::Integer(Integer::from(2)),
        Value::Integer(Integer::from(3)),
    ]);
    let b = Value::Array(vec![
        Value::Integer(Integer::from(3)),
        Value::Integer(Integer::from(2)),
        Value::Integer(Integer::from(1)),
    ]);
    let bytes_a = to_canonical_cbor(&a).expect("anchor [1,2,3] canonicalizes");
    let bytes_b = to_canonical_cbor(&b).expect("anchor [3,2,1] canonicalizes");
    assert_ne!(
        bytes_a, bytes_b,
        "ANCHOR REGRESSION: Value::Array order preservation broken — \
         [1,2,3] and [3,2,1] canonicalize to the same bytes. The Array \
         branch at lib.rs:502-506 is sorting, but arrays MUST preserve \
         insertion order (RFC 8949)."
    );

    // (b) Recursive NaN rejection inside an Array.
    let nan_in_array = Value::Array(vec![
        Value::Integer(Integer::from(0)),
        Value::Float(f64::NAN),
    ]);
    match to_canonical_cbor(&nan_in_array) {
        Err(SerializationError::NonFiniteFloat) => {}
        Err(other) => panic!(
            "ANCHOR: NaN inside Array produced unexpected error {other:?}; \
             expected NonFiniteFloat"
        ),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: Array containing a NaN was accepted by \
             canonicalization — the Array branch is not recursing into \
             elements through canonicalize_value_in_place. An attacker \
             could smuggle distinct NaN bit patterns through the canonical \
             boundary, breaking content-addressing determinism."
        ),
    }

    // (c) Depth: an array nested deeper than MAX_CANONICALIZATION_DEPTH
    // MUST trip DepthExceeded. We construct an array nesting MAX+10 levels.
    let mut deep = Value::Integer(Integer::from(0));
    for _ in 0..(MAX_CANONICALIZATION_DEPTH + 10) {
        deep = Value::Array(vec![deep]);
    }
    match to_canonical_cbor(&deep) {
        Err(SerializationError::DepthExceeded { depth, max })
        | Err(SerializationError::PayloadTooLarge { len: depth, max }) => {
            // Either error is acceptable — the size cap MAX_CANONICAL_OBJECT_BYTES
            // could trip first on truly huge nested structures, but for our
            // nesting (~138) it's the depth gate that fires. Sanity-check at
            // least that we got a typed bounded-resource rejection.
            assert!(
                depth >= MAX_CANONICALIZATION_DEPTH || max == MAX_CANONICAL_OBJECT_BYTES,
                "ANCHOR: depth-rejection gate fired with unexpected (len={depth}, max={max})"
            );
        }
        Err(other) => panic!(
            "ANCHOR: deeply-nested array produced unexpected error {other:?}; \
             expected DepthExceeded"
        ),
        Ok(_) => panic!(
            "ANCHOR REGRESSION: array nested {} levels was accepted — depth \
             counting at lib.rs:485-490 is not incremented on the Array \
             branch (lib.rs:502-506 calls canonicalize_value_in_place with \
             depth+1, which a regression could drop). Stack-exhaustion DoS \
             via deeply-nested arrays now possible.",
            MAX_CANONICALIZATION_DEPTH + 10
        ),
    }
}
