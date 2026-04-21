#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::{Integer, Value};
use fcp_cbor::{MAX_CANONICAL_OBJECT_BYTES, to_canonical_cbor};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 32 * 1024;

// Cap on the arbitrary-built map size to keep the harness fast. The real
// canonicalizer's limits (`MAX_CANONICALIZATION_DEPTH = 128`,
// `MAX_CANONICAL_OBJECT_BYTES = 64 MiB`) are tested independently — here we
// want many small inputs, not few giant ones.
const MAX_ENTRIES_PER_MAP: usize = 64;
const MAX_DEPTH: usize = 6;
const MAX_STRING_LEN: usize = 32;
const MAX_BYTES_LEN: usize = 32;

/// Structure-aware CBOR value generator. Biased toward `Map` so the fuzzer
/// spends its budget on the code path we care about: the `canonicalize_map`
/// sort/dedup/nested-canonicalize pipeline.
fn arbitrary_value(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Value> {
    if depth >= MAX_DEPTH {
        return arbitrary_leaf(u);
    }

    // Bias: Map 50%, Array 20%, leaf 30%. We also avoid `Tag` since the
    // canonicalizer rejects tags (documented behavior; not a canonicalization
    // property to probe here).
    match u.int_in_range::<u8>(0..=9)? {
        0..=4 => arbitrary_map(u, depth),
        5..=6 => arbitrary_array(u, depth),
        _ => arbitrary_leaf(u),
    }
}

fn arbitrary_map(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Value> {
    let n = u.int_in_range::<usize>(0..=MAX_ENTRIES_PER_MAP)?;
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let key = arbitrary_key(u)?;
        let value = arbitrary_value(u, depth + 1)?;
        entries.push((key, value));
    }
    Ok(Value::Map(entries))
}

fn arbitrary_array(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Value> {
    let n = u.int_in_range::<usize>(0..=MAX_ENTRIES_PER_MAP)?;
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        items.push(arbitrary_value(u, depth + 1)?);
    }
    Ok(Value::Array(items))
}

/// Keys exercise the full comparator space: ints, strings, byte strings, and
/// bools. The canonicalizer encodes each key to CBOR and sorts
/// lexicographically, so mixing types surfaces the cross-type ordering.
fn arbitrary_key(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    match u.int_in_range::<u8>(0..=4)? {
        0 => Ok(Value::Integer(Integer::from(u.arbitrary::<i32>()?))),
        1 => {
            let len = u.int_in_range::<usize>(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            Ok(Value::Text(String::from_utf8_lossy(bytes).into_owned()))
        }
        2 => {
            let len = u.int_in_range::<usize>(0..=MAX_BYTES_LEN)?;
            Ok(Value::Bytes(u.bytes(len)?.to_vec()))
        }
        3 => Ok(Value::Bool(u.arbitrary::<bool>()?)),
        _ => Ok(Value::Null),
    }
}

fn arbitrary_leaf(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    match u.int_in_range::<u8>(0..=6)? {
        0 => Ok(Value::Integer(Integer::from(u.arbitrary::<i64>()?))),
        1 => {
            let len = u.int_in_range::<usize>(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            Ok(Value::Text(String::from_utf8_lossy(bytes).into_owned()))
        }
        2 => {
            let len = u.int_in_range::<usize>(0..=MAX_BYTES_LEN)?;
            Ok(Value::Bytes(u.bytes(len)?.to_vec()))
        }
        3 => Ok(Value::Bool(u.arbitrary::<bool>()?)),
        4 => Ok(Value::Null),
        5 => {
            // Avoid NaN: ciborium encodes each NaN bit-pattern distinctly and
            // canonical equivalence across NaNs isn't in scope for this harness.
            let f = u.arbitrary::<f64>()?;
            Ok(Value::Float(if f.is_nan() { 0.0 } else { f }))
        }
        _ => Ok(Value::Integer(Integer::from(u.arbitrary::<u32>()?))),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(value) = arbitrary_value(&mut u, 0) else {
        return;
    };

    // PROPERTY 1: Canonicalization is a bounded operation. It either succeeds
    // (Ok) or returns a typed error (e.g. DuplicateMapKey, DepthExceeded,
    // PayloadTooLarge, UnsupportedTag) — never panics, never hangs.
    let Ok(canonical) = to_canonical_cbor(&value) else {
        return;
    };

    // PROPERTY 2: Size cap. `to_canonical_cbor` MUST refuse to return output
    // larger than MAX_CANONICAL_OBJECT_BYTES; violating this is a DoS vector.
    assert!(
        canonical.len() <= MAX_CANONICAL_OBJECT_BYTES,
        "canonical output {} bytes exceeds MAX_CANONICAL_OBJECT_BYTES ({})",
        canonical.len(),
        MAX_CANONICAL_OBJECT_BYTES
    );

    // PROPERTY 3: Determinism. Canonicalization is by contract deterministic —
    // re-running on the same `Value` must produce byte-identical output.
    let canonical2 = to_canonical_cbor(&value).expect("second canonicalize must succeed");
    assert_eq!(
        canonical, canonical2,
        "canonicalization not deterministic on repeat invocation"
    );

    // PROPERTY 4: Round-trip. Decoding canonical CBOR and re-encoding MUST
    // yield the same bytes. This is the normative RFC 8949 §4.2 property.
    let Ok(decoded) = ciborium::from_reader::<Value, _>(&canonical[..]) else {
        // If we can't decode what we just encoded, that's a crash-class bug.
        panic!("canonical output failed to round-trip through ciborium decoder");
    };

    let recanonical = to_canonical_cbor(&decoded)
        .expect("re-canonicalizing decoded value of prior canonical output must succeed");
    assert_eq!(
        canonical, recanonical,
        "round-trip broken: encode → decode → encode produced different bytes"
    );
});
