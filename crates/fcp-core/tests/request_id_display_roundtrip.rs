//! Pin `RequestId` Display + FromStr round-trip stability across the
//! documented format variants (flywheel_connectors-abr7b).
//!
//! `RequestId(String)` (protocol.rs:34) is the wire-level correlation
//! identifier the Hub and connector echo back to each other. The
//! type's documentation explicitly states the format is NOT
//! prescribed:
//!
//! > On the wire, this is a string like "`req_123`" or a UUID string.
//! > The format is not prescribed; the Hub and connector just need
//! > to echo it back.
//!
//! Documented variants (and a few real-world shapes) all MUST
//! Display→FromStr round-trip identically, since the underlying
//! storage is a free-form String. This test pins:
//!
//! 1. Display emits the constructor input verbatim across every
//!    documented variant: random monotonic (`req_<20-zero-padded>`),
//!    short user-supplied (`req_123`), UUID hyphenated, UUID simple,
//!    arbitrary opaque strings.
//! 2. Display → FromStr round-trip preserves Eq + Hash (FromStr is
//!    Infallible so it always succeeds).
//! 3. Equality + Hash agree across construction paths
//!    (`new` / `From<&str>` / `From<String>` / `FromStr` / `random`
//!    where applicable / `clone`).
//! 4. `RequestId::random()` produces monotonically-distinct ids that
//!    round-trip cleanly.
//! 5. Distinct inputs are distinct RequestIds.
//! 6. HashMap-key correctness across construction paths.
//! 7. Serde JSON round-trip — JSON form is the quoted string.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use fcp_core::RequestId;

fn hash_of<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// Cover the format variants the docs (protocol.rs:30-32) call out
/// plus a few realistic shapes from production fixtures.
const VARIANTS: &[&str] = &[
    // Monotonic-style (matches RequestId::random format).
    "req_00000000000000000001",
    "req_00000000000000999999",
    // Short user-supplied (matches the docs example).
    "req_123",
    "req_456",
    // UUID hyphenated.
    "550e8400-e29b-41d4-a716-446655440000",
    "00000000-0000-0000-0000-000000000000",
    // UUID simple form (no hyphens).
    "550e8400e29b41d4a716446655440000",
    // Opaque correlation tokens — the format is unprescribed.
    "trace-abc-xyz",
    "id.with.dots",
    "id_with_underscores",
    "id-with-hyphens",
    // Mixed-case (no validation; preserved as-is).
    "ReQ_123_AbC",
    // Empty string — no validation, must round-trip.
    "",
    // Single character.
    "x",
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Display emits constructor input verbatim
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_emits_input_verbatim_across_variants() {
    for input in VARIANTS {
        let id = RequestId::new(*input);
        assert_eq!(
            id.to_string(),
            *input,
            "Display MUST emit the constructor input verbatim for {input:?}"
        );
        // The internal pub-field MUST also match.
        assert_eq!(id.0, *input);
    }
}

#[test]
fn display_idempotent_under_repeat_format() {
    for input in VARIANTS {
        let id = RequestId::new(*input);
        let a = id.to_string();
        let b = format!("{id}");
        let c = format!("{id}");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Display → FromStr round-trip preserves Eq + Hash
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_fromstr_roundtrip_preserves_equality_and_hash() {
    for input in VARIANTS {
        let original = RequestId::new(*input);
        let displayed = original.to_string();
        // FromStr is Infallible — always succeeds.
        let rebuilt = RequestId::from_str(&displayed).expect("Infallible");
        assert_eq!(
            original, rebuilt,
            "Display → FromStr round-trip lost equality for {input:?}"
        );
        assert_eq!(
            hash_of(&original),
            hash_of(&rebuilt),
            "Display → FromStr round-trip lost hash for {input:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Equality + Hash across construction paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equality_and_hash_across_construction_paths() {
    for input in VARIANTS {
        let via_new = RequestId::new(*input);
        let via_new_owned = RequestId::new(String::from(*input));
        let via_from_str = RequestId::from_str(input).expect("Infallible");
        let via_from_borrow: RequestId = (*input).into();
        let via_from_owned: RequestId = String::from(*input).into();
        let via_clone = via_new.clone();
        let via_display_rt = RequestId::from_str(&via_new.to_string()).expect("Infallible");

        assert_eq!(via_new, via_new_owned, "{input:?}: &str vs String new");
        assert_eq!(via_new, via_from_str, "{input:?}: FromStr");
        assert_eq!(via_new, via_from_borrow, "{input:?}: From<&str>");
        assert_eq!(via_new, via_from_owned, "{input:?}: From<String>");
        assert_eq!(via_new, via_clone, "{input:?}: clone");
        assert_eq!(via_new, via_display_rt, "{input:?}: Display rt");

        let h = hash_of(&via_new);
        assert_eq!(h, hash_of(&via_new_owned));
        assert_eq!(h, hash_of(&via_from_str));
        assert_eq!(h, hash_of(&via_from_borrow));
        assert_eq!(h, hash_of(&via_from_owned));
        assert_eq!(h, hash_of(&via_clone));
        assert_eq!(h, hash_of(&via_display_rt));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. RequestId::random produces distinct, well-formed, round-trippable ids
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn random_produces_req_prefix_with_20_digit_sequence() {
    // The implementation guarantees `req_<20-digit-zero-padded>`
    // (protocol.rs:46-47). Pin the format so any drift is visible.
    let id = RequestId::random();
    let s = id.to_string();
    assert!(
        s.starts_with("req_"),
        "RequestId::random MUST start with `req_` prefix, got {s}"
    );
    let suffix = s.strip_prefix("req_").unwrap();
    assert_eq!(
        suffix.len(),
        20,
        "RequestId::random MUST produce a 20-digit sequence, got {suffix:?}"
    );
    assert!(
        suffix.chars().all(|c| c.is_ascii_digit()),
        "RequestId::random suffix MUST be all digits: {suffix}"
    );
}

#[test]
fn random_ids_are_pairwise_distinct() {
    // Two consecutive random() calls MUST produce distinct ids
    // (the underlying counter is monotonic).
    let a = RequestId::random();
    let b = RequestId::random();
    let c = RequestId::random();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
    assert_ne!(hash_of(&a), hash_of(&b));
}

#[test]
fn random_ids_round_trip_cleanly() {
    for _ in 0..20 {
        let original = RequestId::random();
        let displayed = original.to_string();
        let rebuilt = RequestId::from_str(&displayed).expect("Infallible");
        assert_eq!(original, rebuilt);
        assert_eq!(hash_of(&original), hash_of(&rebuilt));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Distinct inputs are distinct RequestIds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_inputs_distinct_request_ids() {
    let ids: Vec<RequestId> = VARIANTS.iter().map(|s| RequestId::new(*s)).collect();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(
                ids[i], ids[j],
                "{:?} and {:?} MUST be distinct RequestIds",
                VARIANTS[i], VARIANTS[j]
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. HashMap-key correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn request_id_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<RequestId, &'static str> = HashMap::new();
    map.insert(RequestId::new("req_123"), "first");
    map.insert(
        RequestId::new("550e8400-e29b-41d4-a716-446655440000"),
        "second",
    );
    map.insert(RequestId::new(""), "empty");

    // Look up via fresh Display→FromStr and From<&str> paths.
    let lookup_a = RequestId::from_str("req_123").expect("Infallible");
    let lookup_b: RequestId = "550e8400-e29b-41d4-a716-446655440000".into();
    let lookup_c = RequestId::new(String::new());

    assert_eq!(map.get(&lookup_a), Some(&"first"));
    assert_eq!(map.get(&lookup_b), Some(&"second"));
    assert_eq!(map.get(&lookup_c), Some(&"empty"));
    assert_eq!(map.len(), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Serde JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_form_is_quoted_string() {
    for input in VARIANTS {
        let id = RequestId::new(*input);
        let json = serde_json::to_string(&id).expect("serialize");
        // RequestId derives Serialize on a tuple struct(String); the
        // default is to emit a JSON object `{"0":"..."}` UNLESS
        // the derive treats it as transparent. Pin whichever the
        // current implementation does.
        let back: RequestId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, back, "JSON round-trip lost equality for {input:?}");
        assert_eq!(hash_of(&id), hash_of(&back));
    }
}

#[test]
fn serde_json_form_pinned_for_known_variant() {
    // Pin the exact JSON shape so any future drift in serde derive
    // behavior shows up here. RequestId is a tuple struct(String)
    // without #[serde(transparent)], so the default form is a
    // single-element array: `["req_123"]`.
    let id = RequestId::new("req_pinned");
    let json = serde_json::to_string(&id).expect("serialize");
    // Serde 1.x default for `struct Foo(String)` is to emit just the
    // string (newtype optimization), giving `"req_pinned"`. Pin that.
    assert_eq!(
        json, "\"req_pinned\"",
        "FORMAT REGRESSION: RequestId JSON shape changed; expected newtype string form"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Empty-string edge case
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_request_id_is_supported_and_round_trips() {
    // The docs say the format is unprescribed; the empty string is
    // a degenerate but legal value.
    let empty = RequestId::new("");
    assert_eq!(empty.to_string(), "");
    assert_eq!(empty.0, "");
    let back = RequestId::from_str("").expect("Infallible on empty");
    assert_eq!(empty, back);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Tuple-field access matches Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pub_field_access_matches_display() {
    for input in VARIANTS {
        let id = RequestId::new(*input);
        // The pub field gives direct access; Display emits the same.
        assert_eq!(id.0, id.to_string());
        assert_eq!(id.0, *input);
    }
}
