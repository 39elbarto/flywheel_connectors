#![no_main]

//! Fuzz target for `fcp_crypto::canonicalize::to_deterministic_cbor`
//! and `to_deterministic_cbor_with_capacity` (canonicalize.rs:81-105).
//!
//! These wrap ciborium with FCP's canonical-CBOR normalization rules:
//! - Map keys sorted lexicographically by their canonical encoding
//! - No indefinite-length encoding
//! - Smallest integer encoding
//! - NaN / +∞ / -∞ rejected
//! - -0.0 normalized to +0.0
//! - CBOR tags rejected (not part of FCP serialization surface)
//! - Recursion depth limited to MAX_CANONICALIZATION_DEPTH (128)
//!
//! NOT covered as a discrete unit. `fcp_cbor::to_canonical_cbor` has
//! its own fuzz, but the `fcp_crypto::canonicalize` pathway has a
//! separate `canonicalize_value_in_place` implementation that is the
//! actual primitive driving `Signable::signing_bytes` and quorum
//! signing — divergence between the two would split the canonical
//! form between signing and content-addressing paths.
//!
//! A regression that:
//!   - dropped tag rejection here would let a `Signable` produce
//!     signing bytes containing CBOR tags that downstream content-
//!     address paths would re-canonicalize differently.
//!   - made map-key sort unstable would break multi-implementation
//!     reproducibility of signed objects.
//!   - silently accepted NaN floats would inject non-canonical bit
//!     patterns into the signing transcript.
//!
//! Properties asserted:
//!
//!   1. **Determinism**: `to_deterministic_cbor(v)` returns identical
//!      bytes on repeated calls.
//!   2. **Capacity-prealloc agreement**:
//!      `to_deterministic_cbor(v) == to_deterministic_cbor_with_capacity(v, cap)`
//!      for any `cap`.
//!   3. **Idempotence**: encode → decode → re-encode produces byte-
//!      identical output.
//!   4. **Tag rejection**: a `Value::Tag(...)` input fails with
//!      `CryptoError::SerializationError` (the canonicalize step
//!      rejects tagged values).
//!   5. **NaN rejection**: encoding a `Value::Float(NaN)` fails.
//!   6. **+∞ rejection**: encoding a `Value::Float(+∞)` fails.
//!   7. **-∞ rejection**: encoding a `Value::Float(-∞)` fails.
//!   8. **Map-key sort independent of insertion order**: a map with
//!      the same keys in two different insertion orders MUST produce
//!      identical canonical bytes.
//!
//!   Once-gated anchors verify each rejection branch on hand-picked
//!   inputs.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::{Integer, Value};
use fcp_crypto::CryptoError;
use fcp_crypto::canonicalize::{to_deterministic_cbor, to_deterministic_cbor_with_capacity};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static DETERMINISTIC_CBOR_ANCHOR: Once = Once::new();

const MAX_ENTRIES: usize = 16;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Pairs (raw_key, raw_value); converted into Value::Map entries.
    entries: Vec<(i32, i32)>,
    /// Capacity hint to test capacity-prealloc agreement.
    capacity_hint: u16,
}

fuzz_target!(|data: &[u8]| {
    DETERMINISTIC_CBOR_ANCHOR.call_once(assert_deterministic_cbor_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.entries.len() > MAX_ENTRIES {
        return;
    }

    // Build a Value::Map from the input entries (deduping keys to avoid
    // tripping the duplicate-key gate, which is its own canonicalize
    // failure mode covered elsewhere).
    let mut entries_dedup: Vec<(i32, i32)> = Vec::with_capacity(input.entries.len());
    let mut seen_keys = std::collections::HashSet::new();
    for (k, v) in &input.entries {
        if seen_keys.insert(*k) {
            entries_dedup.push((*k, *v));
        }
    }

    let pairs: Vec<(Value, Value)> = entries_dedup
        .iter()
        .map(|(k, v)| {
            (
                Value::Integer(Integer::from(*k)),
                Value::Integer(Integer::from(*v)),
            )
        })
        .collect();
    let value = Value::Map(pairs.clone());

    // ── PROPERTY 1: determinism ─────────────────────────────────────────
    let bytes_a = to_deterministic_cbor(&value).expect("encode A");
    let bytes_b = to_deterministic_cbor(&value).expect("encode B");
    assert_eq!(bytes_a, bytes_b, "to_deterministic_cbor non-deterministic");

    // ── PROPERTY 2: capacity-prealloc agreement ─────────────────────────
    let bytes_cap = to_deterministic_cbor_with_capacity(&value, input.capacity_hint as usize)
        .expect("encode with capacity");
    assert_eq!(
        bytes_a, bytes_cap,
        "to_deterministic_cbor diverges from to_deterministic_cbor_with_capacity"
    );

    // ── PROPERTY 3: idempotence (encode → decode → re-encode) ───────────
    let decoded: Value = ciborium::de::from_reader(&bytes_a[..]).expect("ciborium decode");
    let re_encoded = to_deterministic_cbor(&decoded).expect("re-encode decoded");
    assert_eq!(
        bytes_a, re_encoded,
        "to_deterministic_cbor not idempotent under encode∘decode∘encode"
    );

    // ── PROPERTY 8: map-key sort independent of insertion order ─────────
    if pairs.len() >= 2 {
        let mut reversed = pairs.clone();
        reversed.reverse();
        let value_rev = Value::Map(reversed);
        let bytes_rev = to_deterministic_cbor(&value_rev).expect("encode reversed");
        assert_eq!(
            bytes_a, bytes_rev,
            "map encoding depends on insertion order — canonical sort broken"
        );
    }
});

/// Once-gated anchors: tag/NaN/Inf rejection on hand-picked inputs +
/// capacity-prealloc agreement on a fixed map.
fn assert_deterministic_cbor_anchored() {
    // (a) Tag rejection.
    let tagged = Value::Tag(42, Box::new(Value::Text("payload".into())));
    match to_deterministic_cbor(&tagged) {
        Err(CryptoError::SerializationError(_)) => {}
        other => panic!(
            "ANCHOR REGRESSION: to_deterministic_cbor on Value::Tag returned {other:?}; expected SerializationError"
        ),
    }

    // (b) NaN rejection.
    let nan = Value::Float(f64::NAN);
    match to_deterministic_cbor(&nan) {
        Err(CryptoError::SerializationError(_)) => {}
        other => panic!(
            "ANCHOR REGRESSION: to_deterministic_cbor on NaN returned {other:?}; expected SerializationError"
        ),
    }

    // (c) +∞ rejection.
    let pos_inf = Value::Float(f64::INFINITY);
    match to_deterministic_cbor(&pos_inf) {
        Err(CryptoError::SerializationError(_)) => {}
        other => panic!(
            "ANCHOR REGRESSION: to_deterministic_cbor on +∞ returned {other:?}; expected SerializationError"
        ),
    }

    // (d) -∞ rejection.
    let neg_inf = Value::Float(f64::NEG_INFINITY);
    match to_deterministic_cbor(&neg_inf) {
        Err(CryptoError::SerializationError(_)) => {}
        other => panic!(
            "ANCHOR REGRESSION: to_deterministic_cbor on -∞ returned {other:?}; expected SerializationError"
        ),
    }

    // (e) Capacity-prealloc agreement on a fixed map.
    let map = Value::Map(vec![
        (
            Value::Integer(Integer::from(2i32)),
            Value::Text("two".into()),
        ),
        (
            Value::Integer(Integer::from(1i32)),
            Value::Text("one".into()),
        ),
        (
            Value::Integer(Integer::from(3i32)),
            Value::Text("three".into()),
        ),
    ]);
    let bytes_default = to_deterministic_cbor(&map).expect("ANCHOR: default-cap encode");
    let bytes_cap0 = to_deterministic_cbor_with_capacity(&map, 0).expect("ANCHOR: cap=0 encode");
    let bytes_cap128 =
        to_deterministic_cbor_with_capacity(&map, 128).expect("ANCHOR: cap=128 encode");
    assert_eq!(
        bytes_default, bytes_cap0,
        "ANCHOR REGRESSION: cap=0 prealloc diverges from default"
    );
    assert_eq!(
        bytes_default, bytes_cap128,
        "ANCHOR REGRESSION: cap=128 prealloc diverges from default"
    );

    // (f) Map-key sort independent of insertion order on a fixed map.
    let map_reverse = Value::Map(vec![
        (
            Value::Integer(Integer::from(3i32)),
            Value::Text("three".into()),
        ),
        (
            Value::Integer(Integer::from(2i32)),
            Value::Text("two".into()),
        ),
        (
            Value::Integer(Integer::from(1i32)),
            Value::Text("one".into()),
        ),
    ]);
    let bytes_reverse = to_deterministic_cbor(&map_reverse).expect("ANCHOR: reverse-order encode");
    assert_eq!(
        bytes_default, bytes_reverse,
        "ANCHOR REGRESSION: canonical map encoding depends on insertion order"
    );
}
