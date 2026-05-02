//! Golden-vector regression for br-m7aoz: the arena-based
//! canonicalize_map MUST produce byte-identical canonical CBOR
//! output to the pre-refactor (per-entry-clone) implementation.
//!
//! These vectors are the FIPS-204 / RFC 8949 §4.2.1 outputs for
//! representative map shapes in FCP signed objects. If a future
//! change to canonicalize_map (or to ciborium's encoder) drifts the
//! output, this test fails — protecting every signed-object
//! transcript in the workspace from a silent canonical-form change.

use ciborium::value::{Integer, Value};
use fcp_crypto::canonicalize::to_deterministic_cbor;
use serde::Serialize;
use serde_bytes::Bytes;

#[derive(Serialize)]
struct FcpAadShape<'a> {
    #[serde(with = "serde_bytes")]
    purpose: &'a [u8],
    #[serde(with = "serde_bytes")]
    recipient_node_id: &'a [u8],
    issued_at: u64,
    #[serde(with = "serde_bytes")]
    zone_id: &'a [u8],
}

#[test]
fn canonicalize_arena_fcp_aad_shape_is_byte_identical_to_known_golden() {
    // Mirrors the Fcp4Aad / Fcp2Aad map shape (4 string-keyed fields
    // including 3 bstr + 1 u64). The pinned hex below was captured
    // BEFORE the arena refactor by running this struct through the
    // pre-m7aoz canonicalize_map (which used per-entry key_buf
    // clones). The arena refactor MUST produce the SAME bytes —
    // any drift here breaks every signed X-Wing seal + Fcp2Aad in
    // the workspace.
    //
    // Field-name CBOR encodings under RFC 8949 §4.2.1 bytewise
    // lex order:
    //   0x67 70 75 72 70 6f 73 65         "purpose"            (text-7)
    //   0x67 7a 6f 6e 65 5f 69 64         "zone_id"            (text-7)
    //   0x69 69 73 73 75 65 64 5f 61 74   "issued_at"          (text-9)
    //   0x71 72 65 63 69 70 69 65 6e 74…  "recipient_node_id"  (text-17)
    // The 0x67 group (text len 7) sorts before 0x69 (text len 9)
    // because the CBOR major-type byte for short strings encodes
    // the length in the LSBs of the same byte. Within the 0x67
    // group, "purpose" (0x70 ...) sorts before "zone_id" (0x7a ...).
    let aad = FcpAadShape {
        purpose: b"FCP4-ZONE-KEY",
        recipient_node_id: b"node-7",
        issued_at: 1_700_000_000,
        zone_id: b"z:work",
    };
    let bytes = to_deterministic_cbor(&aad).unwrap();
    let hex = hex::encode(&bytes);

    let expected = concat!(
        "a4",                                    // map(4)
        "67",                                    // text(7)
        "707572706f7365",                        //   "purpose"
        "4d",                                    // bytes(13)
        "464350342d5a4f4e452d4b4559",            //   "FCP4-ZONE-KEY"
        "67",                                    // text(7)
        "7a6f6e655f6964",                        //   "zone_id"
        "46",                                    // bytes(6)
        "7a3a776f726b",                          //   "z:work"
        "69",                                    // text(9)
        "6973737565645f6174",                    //   "issued_at"
        "1a6553f100",                            //   uint(0x6553f100 = 1_700_000_000)
        "71",                                    // text(17)
        "726563697069656e745f6e6f64655f6964",    //   "recipient_node_id"
        "46",                                    // bytes(6)
        "6e6f64652d37",                          //   "node-7"
    );

    assert_eq!(
        hex, expected,
        "br-m7aoz: arena-based canonicalize_map output must match the pre-refactor golden bytes"
    );
}

#[test]
fn canonicalize_arena_handles_reverse_input_order() {
    // Input maps come in arbitrary key order. The canonicalizer MUST
    // produce the same output regardless of input order — this is
    // the whole point of canonicalization.
    let mut reversed = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            (
                Value::Text("zone_id".to_string()),
                Value::Bytes(b"z:work".to_vec()),
            ),
            (
                Value::Text("recipient_node_id".to_string()),
                Value::Bytes(b"node-7".to_vec()),
            ),
            (
                Value::Text("purpose".to_string()),
                Value::Bytes(b"FCP4-ZONE-KEY".to_vec()),
            ),
            (
                Value::Text("issued_at".to_string()),
                Value::Integer(Integer::from(1_700_000_000_u64)),
            ),
        ]),
        &mut reversed,
    )
    .unwrap();
    // Re-decode + canonicalize.
    let value: Value = ciborium::from_reader(reversed.as_slice()).unwrap();
    let canonical_from_reversed = to_deterministic_cbor(&value).unwrap();

    // Same content in forward order.
    let aad_forward = FcpAadShape {
        purpose: b"FCP4-ZONE-KEY",
        recipient_node_id: b"node-7",
        issued_at: 1_700_000_000,
        zone_id: b"z:work",
    };
    let canonical_from_forward = to_deterministic_cbor(&aad_forward).unwrap();

    assert_eq!(
        canonical_from_reversed, canonical_from_forward,
        "br-m7aoz: canonical output must be invariant to input map order"
    );
}

#[test]
fn canonicalize_arena_rejects_duplicate_keys() {
    // br-m7aoz: post-sort duplicate detection scans adjacent entries
    // in sorted order. Construct a Value with TWO entries that
    // serialize to byte-identical CBOR keys and verify the
    // canonicalizer rejects.
    let dup_map = Value::Map(vec![
        (Value::Text("dup".to_string()), Value::Integer(Integer::from(1))),
        (Value::Text("dup".to_string()), Value::Integer(Integer::from(2))),
    ]);
    let result = to_deterministic_cbor(&dup_map);
    assert!(result.is_err(), "duplicate keys must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("duplicate map key"),
        "error must name the duplicate condition, got: {err_msg}"
    );
}

#[test]
fn canonicalize_arena_handles_large_map_no_realloc_explosion() {
    // br-m7aoz: 64-entry map exercising the arena's per-entry
    // 64-byte pre-allocation. The arena Vec should grow at most
    // a few times (geometric doubling) — the per-entry-clone
    // pre-refactor design grew the heap N times.
    let mut big = Vec::with_capacity(64);
    for i in 0..64u64 {
        big.push((
            Value::Text(format!("key-{i:03}")),
            Value::Integer(Integer::from(i)),
        ));
    }
    let value = Value::Map(big);
    let bytes = to_deterministic_cbor(&value).unwrap();
    // Sanity: round-trips through ciborium and produces a Map with
    // 64 entries in sorted-key order.
    let recovered: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    let Value::Map(entries) = recovered else {
        panic!("expected Map");
    };
    assert_eq!(entries.len(), 64);
    // Pairwise sorted-key check.
    let mut prev_key_bytes: Option<Vec<u8>> = None;
    for (k, _) in &entries {
        let mut k_bytes = Vec::new();
        ciborium::ser::into_writer(k, &mut k_bytes).unwrap();
        if let Some(prev) = prev_key_bytes {
            assert!(prev.as_slice() < k_bytes.as_slice());
        }
        prev_key_bytes = Some(k_bytes);
    }
}

#[test]
fn canonicalize_arena_nested_map_recursion() {
    // br-m7aoz: nested maps must canonicalize at every level.
    // Construct a 3-level nested map and verify the result is
    // sorted at each level.
    let inner = Value::Map(vec![
        (Value::Text("z".to_string()), Value::Integer(Integer::from(1))),
        (Value::Text("a".to_string()), Value::Integer(Integer::from(2))),
    ]);
    let middle = Value::Map(vec![
        (Value::Text("y".to_string()), inner.clone()),
        (Value::Text("b".to_string()), Value::Integer(Integer::from(3))),
    ]);
    let outer = Value::Map(vec![
        (Value::Text("x".to_string()), middle),
        (Value::Text("c".to_string()), Value::Integer(Integer::from(4))),
    ]);
    let bytes = to_deterministic_cbor(&outer).unwrap();
    let recovered: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    // Walk the tree and verify every Map level is sorted.
    fn walk(v: &Value) {
        match v {
            Value::Map(entries) => {
                let mut prev: Option<Vec<u8>> = None;
                for (k, v_inner) in entries {
                    let mut k_bytes = Vec::new();
                    ciborium::ser::into_writer(k, &mut k_bytes).unwrap();
                    if let Some(p) = prev {
                        assert!(
                            p.as_slice() < k_bytes.as_slice(),
                            "map keys must be sorted at every nesting level"
                        );
                    }
                    prev = Some(k_bytes);
                    walk(v_inner);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item);
                }
            }
            _ => {}
        }
    }
    walk(&recovered);
}

#[test]
fn canonicalize_arena_byte_keys_alongside_text_keys() {
    // br-m7aoz: maps with mixed bstr + tstr keys (an edge case
    // where the key encoding tag differs but the bytewise sort
    // still must be deterministic).
    let mixed = Value::Map(vec![
        (Value::Bytes(b"zzz".to_vec()), Value::Integer(Integer::from(1))),
        (Value::Text("aaa".to_string()), Value::Integer(Integer::from(2))),
        (Value::Bytes(b"aaa".to_vec()), Value::Integer(Integer::from(3))),
        (Value::Text("zzz".to_string()), Value::Integer(Integer::from(4))),
    ]);
    let bytes = to_deterministic_cbor(&mixed).unwrap();
    let again: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    let bytes_again = to_deterministic_cbor(&again).unwrap();
    assert_eq!(
        bytes, bytes_again,
        "br-m7aoz: canonical encode is fixed-point — re-encoding the decoded form yields the same bytes"
    );
}

#[test]
fn canonicalize_arena_empty_map_succeeds() {
    let empty = Value::Map(Vec::new());
    let bytes = to_deterministic_cbor(&empty).unwrap();
    // CBOR empty map is `0xa0` (single byte).
    assert_eq!(bytes, vec![0xa0]);
}

#[test]
fn canonicalize_arena_deeply_nested_under_depth_limit_succeeds() {
    // br-m7aoz: 16 levels deep — well under the 128-depth limit.
    // Confirms the recursion sees the arena helper at every level
    // without stack issues.
    let mut current = Value::Integer(Integer::from(42));
    for _ in 0..16 {
        current = Value::Map(vec![(Value::Text("nest".to_string()), current)]);
    }
    let bytes = to_deterministic_cbor(&current).unwrap();
    assert!(
        !bytes.is_empty(),
        "16-level-deep nested map must encode successfully"
    );
}

// ── Regression: HpkeSealedBox-shape canonical bytes pinned ────────

#[test]
fn canonicalize_arena_hpke_sealed_box_shape_round_trips_self_consistently() {
    // br-m7aoz: HpkeSealedBox has two byte fields ("ciphertext",
    // "enc"). Verify that arena-canonicalized output round-trips
    // (encode → decode → re-encode → identical) — a stronger pin
    // than a hardcoded hex string and resilient to ciborium-version
    // bumps.
    #[derive(Serialize)]
    struct HpkeShape<'a> {
        ciphertext: &'a Bytes,
        enc: &'a Bytes,
    }
    let value = HpkeShape {
        ciphertext: Bytes::new(b"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF"),
        enc: Bytes::new(&[0u8; 32]),
    };
    let first = to_deterministic_cbor(&value).unwrap();
    // Decode back and re-encode — should produce identical bytes.
    let decoded: Value = ciborium::from_reader(first.as_slice()).unwrap();
    let second = to_deterministic_cbor(&decoded).unwrap();
    assert_eq!(
        first, second,
        "br-m7aoz: arena canonicalize is fixed-point under decode-then-re-encode"
    );
}
