#![no_main]

//! Metamorphic fuzz target for `fcp_cbor` map canonicalization (lib.rs:515-581).
//!
//! `canonicalize_map` implements RFC 8949 §4.2.3: keys are CBOR-encoded then
//! lexicographically sorted by encoded bytes, and pairs whose canonical-key
//! bytes collide are rejected as `DuplicateMapKey`.
//!
//! Existing `fuzz_canonicalize_map_deterministic` covers same-`Value`
//! determinism, encode→decode→encode round-trip, and the size cap. The
//! metamorphic relations a regression would silently break are NOT
//! covered there; this target adds them:
//!
//!   1. **Permutation invariance**: a map built with key/value pairs in
//!      one order MUST canonicalize to the same bytes as the same pairs
//!      in any other order. A regression that used insertion-order
//!      rather than encoded-key-byte order would still pass determinism
//!      and round-trip but break this MR — and would silently produce
//!      ObjectIds that vary by upstream insertion order.
//!
//!   2. **Duplicate-key rejection**: a `Value::Map` (which is a `Vec`,
//!      not a deduplicating `HashMap`) containing two pairs whose
//!      CBOR-encoded keys are byte-equal MUST be rejected with
//!      `DuplicateMapKey`. Construction can carry duplicates that must
//!      be caught at canonicalization time.
//!
//!   3. **Cross-type lex ordering**: the canonical sort is on encoded
//!      bytes, not on `Value`'s `Ord` impl. Integer 0, byte string `b""`,
//!      string `""`, bool `false`, and `null` all encode to distinct
//!      single-byte CBOR heads, and the canonical sort orders them by
//!      those head bytes. This is asserted as a once-gated regression
//!      anchor against the cross-type ordering invariant.

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::{Integer, Value};
use fcp_cbor::{SerializationError, to_canonical_cbor};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ENTRIES: usize = 32;
const MAX_KEY_LEN: usize = 24;

static CROSS_TYPE_ORDERING_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Up to MAX_ENTRIES distinct keys; values immaterial to the MRs.
    raw: Vec<u8>,
    /// Permutation seed for shuffling the entry order.
    perm_seed: u64,
}

/// Build a map of distinct keys (deduplicated by encoded-byte equality
/// post hoc isn't necessary here; we emit type/length-tagged distinct
/// keys so the fuzzer focuses budget on permutation invariance, and a
/// separate code path below probes the duplicate-rejection MR).
fn build_distinct_map(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<(Value, Value)>> {
    let n = u.int_in_range::<usize>(0..=MAX_ENTRIES)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // Tag each key with its index — this guarantees uniqueness in the
        // permutation-MR path so we don't lose iterations to the
        // duplicate-rejection branch.
        let kind = u.int_in_range::<u8>(0..=3)?;
        let key = match kind {
            0 => Value::Integer(Integer::from(i as i64)),
            1 => {
                let len = u.int_in_range::<usize>(0..=MAX_KEY_LEN)?;
                let mut s = String::with_capacity(len + 4);
                s.push_str(&format!("k{i}_"));
                s.push_str(&String::from_utf8_lossy(u.bytes(len)?));
                Value::Text(s)
            }
            2 => {
                let len = u.int_in_range::<usize>(0..=MAX_KEY_LEN)?;
                let mut b = vec![(i & 0xff) as u8, ((i >> 8) & 0xff) as u8];
                b.extend_from_slice(u.bytes(len)?);
                Value::Bytes(b)
            }
            _ => Value::Integer(Integer::from(-(i as i64) - 1)),
        };
        out.push((key, Value::Integer(Integer::from(i as i64))));
    }
    Ok(out)
}

/// xorshift64 PRNG so we can deterministically permute under the fuzzer
/// without pulling in an RNG crate. Permutation just needs to be a
/// bijection driven by an arbitrary seed; this is fine.
fn shuffle<T>(items: &mut [T], mut state: u64) {
    if items.len() < 2 {
        return;
    }
    if state == 0 {
        state = 0xdead_beef_cafe_babe;
    }
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state as usize) % (i + 1);
        items.swap(i, j);
    }
}

fuzz_target!(|data: &[u8]| {
    CROSS_TYPE_ORDERING_ANCHOR.call_once(assert_cross_type_ordering_anchored);

    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    let mut u = Unstructured::new(&input.raw);

    let Ok(entries) = build_distinct_map(&mut u) else {
        return;
    };

    // ── PROPERTY 1: permutation invariance ─────────────────────────────
    let original = Value::Map(entries.clone());
    let Ok(canonical_orig) = to_canonical_cbor(&original) else {
        // The original may carry duplicates by encoded-byte collision (e.g.,
        // distinct Value-level keys encoding to identical bytes). That's the
        // duplicate-rejection MR's branch, not a permutation regression.
        return;
    };

    let mut shuffled_entries = entries.clone();
    shuffle(&mut shuffled_entries, input.perm_seed);
    let shuffled = Value::Map(shuffled_entries);
    let canonical_shuf = to_canonical_cbor(&shuffled)
        .expect("shuffled map of the same distinct entries must canonicalize identically");
    assert_eq!(
        canonical_orig, canonical_shuf,
        "canonicalize_map is not permutation-invariant — input ordering \
         leaked into canonical bytes; ObjectIds would vary by insertion order"
    );

    // ── PROPERTY 2: duplicate-key rejection ────────────────────────────
    // Take any non-empty entries vec and append an exact duplicate key.
    // canonicalize_map MUST reject with DuplicateMapKey.
    if let Some((dup_key, _)) = entries.first().cloned() {
        let mut with_dup = entries.clone();
        // Append a pair with the same key (clone) and a sentinel value.
        with_dup.push((dup_key, Value::Integer(Integer::from(i64::MIN))));
        let map_with_dup = Value::Map(with_dup);
        match to_canonical_cbor(&map_with_dup) {
            Err(SerializationError::DuplicateMapKey { .. }) => {}
            Err(other) => {
                // Other typed errors (e.g., PayloadTooLarge) are allowed if
                // they fire first on adversarial input — they are not the
                // surface this MR probes. Specifically, NaN or unsupported
                // tag would have tripped the value-leg path earlier, but
                // we constructed values from finite ints only.
                let _ = other;
            }
            Ok(_) => panic!(
                "canonicalize_map accepted a map containing two pairs with \
                 byte-identical canonical keys — DuplicateMapKey rejection lost"
            ),
        }
    }
});

/// Once-gated anchor for the cross-type lex-ordering MR. We construct a
/// map that mixes one key of every primitive type and assert the
/// canonical bytes match the order RFC 8949 §4.2.3 prescribes
/// (lex-on-encoded-bytes), regardless of any Rust-level Ord impl.
///
/// This trips on every run if a regression delegates the sort to
/// `Value::cmp` instead of comparing the encoded scratch ranges
/// (lib.rs:556-560).
fn assert_cross_type_ordering_anchored() {
    use ciborium::de::from_reader;

    // Five keys with distinct CBOR head bytes:
    //   integer 0       → 0x00
    //   bytes b""       → 0x40
    //   text ""         → 0x60
    //   bool false      → 0xf4
    //   null            → 0xf6
    //
    // Lex order on encoded bytes: 0x00 < 0x40 < 0x60 < 0xf4 < 0xf6.
    // We feed them in a deliberately reversed insertion order so a
    // by-insertion regression would visibly break this anchor.
    let entries = vec![
        (Value::Null, Value::Integer(Integer::from(4))),
        (Value::Bool(false), Value::Integer(Integer::from(3))),
        (Value::Text(String::new()), Value::Integer(Integer::from(2))),
        (Value::Bytes(vec![]), Value::Integer(Integer::from(1))),
        (
            Value::Integer(Integer::from(0)),
            Value::Integer(Integer::from(0)),
        ),
    ];
    let map = Value::Map(entries);
    let canonical = to_canonical_cbor(&map).expect("anchor map canonicalizes");

    // Decode and verify the keys appear in the expected RFC-prescribed
    // order. We look at the value sequence (0,1,2,3,4) which mirrors
    // the key order (int 0, bytes, text, bool, null).
    let decoded: Value =
        from_reader(&canonical[..]).expect("anchor canonical bytes decode as Value");
    let Value::Map(decoded_entries) = decoded else {
        panic!("anchor decoded to non-Map");
    };
    let value_seq: Vec<i64> = decoded_entries
        .iter()
        .filter_map(|(_, v)| match v {
            Value::Integer(i) => i64::try_from(*i).ok(),
            _ => None,
        })
        .collect();
    assert_eq!(
        value_seq,
        vec![0, 1, 2, 3, 4],
        "cross-type canonical ordering broken: keys did not sort by encoded \
         bytes (RFC 8949 §4.2.3) — likely Value::cmp regression at lib.rs:556-560. \
         Expected (int 0, bytes, text, bool, null) → values (0,1,2,3,4); got {value_seq:?}"
    );
}
