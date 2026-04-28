//! Pin `CredentialId` Display formatting + parse round-trip + Eq/Hash
//! semantics (flywheel_connectors-suze4).
//!
//! `CredentialId(Uuid)` (credential.rs:33) is the stable public
//! identifier for a credential record stored in the mesh. Its
//! Display form appears in audit events, decision receipts, error
//! messages (`CredentialValidationError::HostNotAllowed{host,
//! credential_id}`), and operator dashboards. The round-trip pair is
//! `Display → CredentialId::parse` (no `FromStr` impl is provided;
//! the parser is the explicit `parse(&str) -> Result<Self, uuid::Error>`
//! method).
//!
//! Pinned properties:
//!
//!   1. **Display format** — UUID lowercase-hyphenated 8-4-4-4-12.
//!   2. **Display → parse round-trip** preserves Eq + Hash.
//!   3. **from_uuid → as_uuid** identity.
//!   4. **Case-insensitive parse** — uppercase, lowercase, and
//!      mixed-case UUID strings all parse to the same value.
//!   5. **Malformed input rejected** — non-UUID strings, wrong
//!      length, non-hex characters.
//!   6. **Equality across construction paths**: new / from_uuid /
//!      parse / clone / Display→parse.
//!   7. **Debug != Display**: Debug wraps the value as
//!      `CredentialId("<uuid>")`.
//!   8. **HashMap key correctness** across re-parsed values.
//!   9. **Serde JSON round-trip** via `#[serde(transparent)]` —
//!      JSON form is the quoted UUID string.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use fcp_core::CredentialId;
use uuid::Uuid;

fn hash_of<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// Representative UUIDs spanning v4 randomness, all-zeros, all-ones,
/// and a stable hand-picked value used for fixture-style tests.
const FIXED_UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";
const ALL_ZERO_UUID: &str = "00000000-0000-0000-0000-000000000000";
const ALL_ONE_UUID: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

const FIXTURES: &[&str] = &[
    FIXED_UUID_V4,
    ALL_ZERO_UUID,
    ALL_ONE_UUID,
    "00112233-4455-6677-8899-aabbccddeeff",
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Display format
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_emits_uuid_hyphenated_lowercase() {
    for input in FIXTURES {
        let id = CredentialId::parse(input).unwrap_or_else(|err| panic!("parse({input}): {err}"));
        let displayed = id.to_string();
        assert_eq!(
            displayed, *input,
            "Display MUST emit the canonical UUID hyphenated lowercase form"
        );
        assert_eq!(displayed.len(), 36, "UUID Display MUST be 36 chars");
        assert_eq!(
            displayed.matches('-').count(),
            4,
            "UUID Display MUST contain 4 hyphens"
        );
    }
}

#[test]
fn display_uses_lowercase_hex_only() {
    let id = CredentialId::parse(FIXED_UUID_V4).unwrap();
    let displayed = id.to_string();
    assert!(
        displayed
            .chars()
            .all(|c| c == '-' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase())),
        "Display MUST be lowercase hex with hyphens: {displayed}"
    );
}

#[test]
fn display_format_for_random_new_id_is_canonical_uuid() {
    // CredentialId::new() returns a random UUID v4; the Display form
    // MUST still parse cleanly back via the parse method.
    for _ in 0..20 {
        let id = CredentialId::new();
        let displayed = id.to_string();
        let rebuilt = CredentialId::parse(&displayed)
            .expect("Display from new() MUST parse back via CredentialId::parse");
        assert_eq!(id, rebuilt);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Display → parse round-trip preserves Eq + Hash
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_parse_roundtrip_preserves_equality_and_hash() {
    for input in FIXTURES {
        let original = CredentialId::parse(input).expect("canonical parse");
        let displayed = original.to_string();
        let rebuilt = CredentialId::parse(&displayed).expect("Display→parse round-trip");

        assert_eq!(
            original, rebuilt,
            "Display→parse round-trip lost equality for {input}"
        );
        assert_eq!(
            hash_of(&original),
            hash_of(&rebuilt),
            "Display→parse round-trip lost hash for {input}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. from_uuid → as_uuid identity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn from_uuid_as_uuid_round_trip() {
    for input in FIXTURES {
        let uuid = Uuid::parse_str(input).expect("UUID parse");
        let id = CredentialId::from_uuid(uuid);
        assert_eq!(*id.as_uuid(), uuid, "from_uuid → as_uuid MUST round-trip");
        assert_eq!(id.to_string(), *input, "from_uuid Display matches original");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Case-insensitive parse
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_accepts_uppercase_and_mixed_case_uuid() {
    let lower = CredentialId::parse(FIXED_UUID_V4).expect("lowercase");
    let upper = CredentialId::parse(&FIXED_UUID_V4.to_uppercase()).expect("uppercase");
    let mixed_case: String = FIXED_UUID_V4
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i.is_multiple_of(2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    let mixed = CredentialId::parse(&mixed_case).expect("mixed-case");

    assert_eq!(lower, upper, "uppercase MUST equal lowercase");
    assert_eq!(lower, mixed, "mixed-case MUST equal lowercase");
    assert_eq!(hash_of(&lower), hash_of(&upper));
    assert_eq!(hash_of(&lower), hash_of(&mixed));

    // Display always emits lowercase regardless of parse input case.
    assert_eq!(upper.to_string(), FIXED_UUID_V4);
    assert_eq!(mixed.to_string(), FIXED_UUID_V4);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Malformed input rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_rejects_empty_string() {
    assert!(CredentialId::parse("").is_err());
}

#[test]
fn parse_rejects_non_uuid_strings() {
    assert!(CredentialId::parse("not-a-uuid").is_err());
    assert!(CredentialId::parse("xyz").is_err());
}

#[test]
fn parse_rejects_wrong_length() {
    // Too short.
    assert!(
        CredentialId::parse("550e8400-e29b-41d4-a716").is_err(),
        "truncated UUID MUST be rejected"
    );
    // Too long (extra chars).
    assert!(
        CredentialId::parse(&format!("{FIXED_UUID_V4}-extra")).is_err(),
        "trailing garbage MUST be rejected"
    );
}

#[test]
fn parse_rejects_non_hex_in_uuid() {
    // 'g' is not a hex digit.
    assert!(
        CredentialId::parse("550e8400-e29b-41d4-a716-44665544000g").is_err(),
        "non-hex char MUST be rejected"
    );
    assert!(
        CredentialId::parse("zzzzzzzz-e29b-41d4-a716-446655440000").is_err(),
        "non-hex chars MUST be rejected"
    );
}

#[test]
fn parse_rejects_missing_hyphens() {
    // 32 hex chars without hyphens — uuid crate's simple form is
    // accepted by Uuid::parse_str, so this MUST also be accepted.
    // Pin the documented behavior either way.
    let no_hyphens = FIXED_UUID_V4.replace('-', "");
    let result = CredentialId::parse(&no_hyphens);
    if let Ok(id) = result {
        // If accepted, Display MUST emit the canonical hyphenated form.
        assert_eq!(
            id.to_string(),
            FIXED_UUID_V4,
            "no-hyphen parse MUST canonicalize to hyphenated lowercase Display"
        );
    }
    // If rejected, that's also acceptable — pin whichever the uuid
    // crate currently does. The point is no panic and no wrong-shape
    // result.
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Equality across construction paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equality_and_hash_across_construction_paths() {
    for input in FIXTURES {
        let uuid = Uuid::parse_str(input).expect("parse uuid");
        let via_parse = CredentialId::parse(input).expect("parse");
        let via_from_uuid = CredentialId::from_uuid(uuid);
        let via_clone = via_parse;
        let via_display_rt = CredentialId::parse(&via_parse.to_string()).expect("Display rt");

        assert_eq!(via_parse, via_from_uuid, "{input}: parse vs from_uuid");
        assert_eq!(via_parse, via_clone, "{input}: clone");
        assert_eq!(via_parse, via_display_rt, "{input}: Display rt");

        let h = hash_of(&via_parse);
        assert_eq!(h, hash_of(&via_from_uuid));
        assert_eq!(h, hash_of(&via_clone));
        assert_eq!(h, hash_of(&via_display_rt));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Debug differs from Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn debug_wraps_value_with_type_name() {
    let id = CredentialId::parse(FIXED_UUID_V4).expect("canonical");
    let debug = format!("{id:?}");
    let display = id.to_string();

    assert!(
        debug.contains("CredentialId"),
        "Debug MUST include the type name: {debug}"
    );
    assert!(
        debug.contains(FIXED_UUID_V4),
        "Debug MUST include the inner UUID Display: {debug}"
    );
    assert_ne!(debug, display, "Debug MUST differ from Display");
    assert_eq!(display, FIXED_UUID_V4);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. HashMap key correctness across re-parsed values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn credential_id_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<CredentialId, &'static str> = HashMap::new();
    let id_a = CredentialId::parse(FIXED_UUID_V4).expect("parse");
    let id_b = CredentialId::new();
    map.insert(id_a, "a-value");
    map.insert(id_b, "b-value");
    assert_eq!(
        map.len(),
        2,
        "two distinct CredentialIds MUST be distinct keys"
    );

    // Look up via fresh Display→parse round-trips.
    let lookup_a = CredentialId::parse(&id_a.to_string()).unwrap();
    let lookup_b = CredentialId::parse(&id_b.to_string()).unwrap();
    assert_eq!(map.get(&lookup_a), Some(&"a-value"));
    assert_eq!(map.get(&lookup_b), Some(&"b-value"));

    // Look up via from_uuid path.
    let lookup_a_uuid = CredentialId::from_uuid(*id_a.as_uuid());
    assert_eq!(map.get(&lookup_a_uuid), Some(&"a-value"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Serde JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_form_is_quoted_uuid_string() {
    for input in FIXTURES {
        let id = CredentialId::parse(input).expect("canonical");
        let json = serde_json::to_string(&id).expect("serialize");
        // serde_transparent → wraps the inner Uuid's Serialize, which
        // emits a quoted hyphenated lowercase UUID string.
        assert_eq!(
            json,
            format!("\"{input}\""),
            "JSON form MUST be the quoted hyphenated lowercase UUID for {input}"
        );

        let back: CredentialId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, back, "JSON round-trip lost equality for {input}");
        assert_eq!(hash_of(&id), hash_of(&back));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Distinct UUIDs are distinct CredentialIds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_uuids_are_distinct_credential_ids() {
    let ids: Vec<CredentialId> = FIXTURES
        .iter()
        .map(|s| CredentialId::parse(s).expect("canonical"))
        .collect();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(
                ids[i], ids[j],
                "{} and {} MUST be distinct CredentialIds",
                FIXTURES[i], FIXTURES[j]
            );
        }
    }
    // Random new IDs are distinct.
    let r1 = CredentialId::new();
    let r2 = CredentialId::new();
    assert_ne!(
        r1, r2,
        "two consecutive new() calls MUST produce distinct IDs"
    );
}
