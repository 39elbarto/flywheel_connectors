#![no_main]

//! Fuzz target for CBOR simple-value (Major Type 7) canonical encoding
//! per RFC 8949 §3.3.
//!
//! Documented byte encodings:
//!   - false → 0xf4
//!   - true  → 0xf5
//!   - null  → 0xf6
//!
//! Existing fcp-cbor canonical-encoding coverage (`cbor_int_canonical_length`,
//! `cbor_string_canonical_length`, `cbor_map_array_canonical_length`,
//! `cbor_map_canonical_relations`, `cbor_array_canonical`,
//! `cbor_float_canonical`, `cbor_float_encoding_edges`,
//! `cbor_tag_rejection`, `cbor_decode_recursion_limit`,
//! `canonical_serializer_schema_binding`) covers integers, strings,
//! arrays, maps, floats, tags, schema gates — but NOT simple-value
//! byte-position anchors.
//!
//! A regression in any of the three simple-value head bytes would break
//! cross-implementation interop and silently shift content addresses
//! for any object containing a Bool or Null.
//!
//! Properties asserted:
//!
//!   1. **bool false** → exactly `[0xf4]`.
//!   2. **bool true**  → exactly `[0xf5]`.
//!   3. **null**       → exactly `[0xf6]`.
//!   4. **Injectivity**: the three encodings are pairwise distinct.
//!   5. **Ciborium round-trip**: decoding each encoding recovers the
//!      original variant.
//!
//!   Once-gated regression anchors verify exact bytes for each simple
//!   value at root AND nested inside Array (where the head byte
//!   appears at index 1 after the Array(1) head 0x81).

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use fcp_cbor::to_canonical_cbor;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static SIMPLE_VALUE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Discriminator: 0=false, 1=true, 2=null, 3=array-of-simple.
    disc: u8,
    inner_disc: u8,
}

fn pick_simple(disc: u8) -> Value {
    match disc % 3 {
        0 => Value::Bool(false),
        1 => Value::Bool(true),
        _ => Value::Null,
    }
}

fn expected_byte(value: &Value) -> u8 {
    match value {
        Value::Bool(false) => 0xf4,
        Value::Bool(true) => 0xf5,
        Value::Null => 0xf6,
        _ => panic!("expected simple value, got {value:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    SIMPLE_VALUE_ANCHOR.call_once(assert_simple_value_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    if input.disc % 4 == 3 {
        // Array of simple value at index 0.
        let inner = pick_simple(input.inner_disc);
        let arr = Value::Array(vec![inner.clone()]);
        let bytes = to_canonical_cbor(&arr).expect("encode array of simple");
        assert_eq!(bytes.len(), 2, "array of one simple should be 2 bytes");
        assert_eq!(bytes[0], 0x81, "array(1) head expected 0x81");
        assert_eq!(
            bytes[1],
            expected_byte(&inner),
            "simple-value at array index 0 wrong byte"
        );
        return;
    }

    // ── PROPERTY 1+2+3: documented byte encoding ─────────────────────
    let v = pick_simple(input.disc);
    let bytes = to_canonical_cbor(&v).expect("encode simple");
    assert_eq!(bytes.len(), 1, "simple value should be 1 byte");
    assert_eq!(
        bytes[0],
        expected_byte(&v),
        "simple {v:?} encoded to 0x{:02x}; expected 0x{:02x}",
        bytes[0],
        expected_byte(&v)
    );

    // ── PROPERTY 5: ciborium round-trip ──────────────────────────────
    let decoded: Value = ciborium::from_reader(&bytes[..]).expect("ciborium decode");
    match (&v, &decoded) {
        (Value::Bool(a), Value::Bool(b)) => assert_eq!(a, b, "Bool round-trip"),
        (Value::Null, Value::Null) => {}
        _ => panic!("simple-value type drift: {v:?} → {decoded:?}"),
    }
});

/// Once-gated anchors verifying exact byte encodings.
fn assert_simple_value_anchored() {
    // Root-level encodings.
    let false_bytes = to_canonical_cbor(&false).expect("anchor false");
    assert_eq!(
        false_bytes,
        vec![0xf4],
        "ANCHOR REGRESSION: bool false encoded to {false_bytes:?}; expected [0xf4]"
    );

    let true_bytes = to_canonical_cbor(&true).expect("anchor true");
    assert_eq!(
        true_bytes,
        vec![0xf5],
        "ANCHOR REGRESSION: bool true encoded to {true_bytes:?}; expected [0xf5]"
    );

    let null_bytes = to_canonical_cbor(&Value::Null).expect("anchor null");
    assert_eq!(
        null_bytes,
        vec![0xf6],
        "ANCHOR REGRESSION: null encoded to {null_bytes:?}; expected [0xf6]"
    );

    // Property 4: injectivity.
    assert_ne!(false_bytes, true_bytes, "ANCHOR: false == true bytes");
    assert_ne!(false_bytes, null_bytes, "ANCHOR: false == null bytes");
    assert_ne!(true_bytes, null_bytes, "ANCHOR: true == null bytes");

    // Nested inside Array: the head byte appears at index 1.
    let arr_false =
        to_canonical_cbor(&Value::Array(vec![Value::Bool(false)])).expect("anchor array(false)");
    assert_eq!(
        arr_false,
        vec![0x81, 0xf4],
        "ANCHOR: array of [false] should be [0x81, 0xf4]; got {arr_false:?}"
    );

    let arr_true =
        to_canonical_cbor(&Value::Array(vec![Value::Bool(true)])).expect("anchor array(true)");
    assert_eq!(
        arr_true,
        vec![0x81, 0xf5],
        "ANCHOR: array of [true] should be [0x81, 0xf5]; got {arr_true:?}"
    );

    let arr_null = to_canonical_cbor(&Value::Array(vec![Value::Null])).expect("anchor array(null)");
    assert_eq!(
        arr_null,
        vec![0x81, 0xf6],
        "ANCHOR: array of [null] should be [0x81, 0xf6]; got {arr_null:?}"
    );
}
