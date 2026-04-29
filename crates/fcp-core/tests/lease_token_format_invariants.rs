//! Pin lease-related identifier + purpose-tag format invariants
//! (flywheel_connectors-5ktrj).
//!
//! Bead asks for `LeaseToken Display+FromStr roundtrip + format
//! constraints`. No type literally named `LeaseToken` exists in
//! fcp-core. The token-shaped surface around leases is split across
//! two existing types:
//!
//!  - `LeaseId` (lease.rs:150 — type alias for `ObjectId`) — which
//!    has Display + std::str::FromStr through `ObjectId`. This is
//!    the closest "token-with-FromStr" analogue.
//!  - `LeasePurpose` (lease.rs:53) — six-variant enum that has
//!    `Display` (hand-written snake_case tokens at lease.rs:68) but
//!    NOT std::str::FromStr. Round-trip on the purpose tag is via
//!    serde JSON deserialization, NOT via a `parse::<LeasePurpose>()`
//!    call.
//!
//! Tests pin the format invariants both surfaces actually carry:
//!
//!   1. **`LeasePurpose` Display token pinned per variant** — the
//!      operator-facing snake_case strings at lease.rs:71-76 used in
//!      audit logs.
//!   2. **Display agrees with serde JSON tag form** — both produce
//!      the same snake_case bytes per variant.
//!   3. **JSON round-trip** preserves variant identity.
//!   4. **Serde JSON acts as the FromStr substitute** — accepting
//!      every Display token and rejecting PascalCase + unknown.
//!   5. **CBOR round-trip** preserves variant.
//!   6. **Hash + Eq + Copy correctness** for use as HashMap keys.
//!   7. **Pairwise distinct variants** — Display strings + hashes.
//!   8. **`LeaseId` Display + FromStr round-trip** — the actual
//!      `parse::<LeaseId>()`-able token form. Both bare-hex and
//!      `objectid:<hex>` forms accepted, exposing the documented
//!      prefix-stripping in `ObjectId::parse_prefixed`.
//!   9. **`LeaseId` parse rejects malformed input** — wrong length,
//!      non-hex, etc.
//!  10. **`to_prefixed_string` produces the canonical
//!      `objectid:<hex>` form** that round-trips back through
//!      FromStr.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use fcp_core::{LeaseId, LeasePurpose, ObjectId};

const ALL_PURPOSES: &[(LeasePurpose, &str)] = &[
    (LeasePurpose::OperationExecution, "operation_execution"),
    (LeasePurpose::ConnectorStateWrite, "connector_state_write"),
    (LeasePurpose::ComputationMigration, "computation_migration"),
    (LeasePurpose::CoordinatorElection, "coordinator_election"),
    (LeasePurpose::Migration, "migration"),
    (LeasePurpose::ResourceAccess, "resource_access"),
];

fn hash_of<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. LeasePurpose Display per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_purpose_display_token_pinned_per_variant() {
    // Tokens pinned at lease.rs:71-76; audit logs filter on these.
    for (variant, expected) in ALL_PURPOSES {
        assert_eq!(
            variant.to_string(),
            *expected,
            "AUDIT REGRESSION: LeasePurpose Display drift on {variant:?}"
        );
        assert_eq!(format!("{variant}"), *expected, "format!() agrees");
    }
}

#[test]
fn lease_purpose_variant_count_matches_six_documented() {
    assert_eq!(
        ALL_PURPOSES.len(),
        6,
        "LeasePurpose has 6 documented variants — count drifted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Display agrees with serde JSON tag form
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_agrees_with_serde_snake_case_tag() {
    // The enum carries `#[serde(rename_all = "snake_case")]` so the
    // wire form MUST match the hand-written Display tokens byte-
    // for-byte. Drift here breaks log/wire compatibility silently.
    for (variant, expected) in ALL_PURPOSES {
        let display = variant.to_string();
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "JSON tag drift on {variant:?}"
        );
        // Strip the JSON quotes to compare with Display.
        let stripped = json.trim_matches('"');
        assert_eq!(
            stripped, display,
            "Display vs serde tag MUST agree byte-for-byte for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. JSON round-trip preserves variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_every_purpose_variant() {
    for (variant, _) in ALL_PURPOSES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: LeasePurpose = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back, "JSON round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Serde JSON acts as the FromStr substitute
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_accepts_every_display_token_as_input() {
    // LeasePurpose does NOT impl std::str::FromStr — round-trip
    // from a "string in" form is via serde, where the JSON literal
    // for each variant is the Display token wrapped in quotes.
    for (variant, expected_token) in ALL_PURPOSES {
        let input = format!("\"{expected_token}\"");
        let parsed: LeasePurpose =
            serde_json::from_str(&input).unwrap_or_else(|err| panic!("deserialize {input}: {err}"));
        assert_eq!(parsed, *variant, "serde round-trip via Display token");
    }
}

#[test]
fn serde_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""OperationExecution""#,
        r#""ConnectorStateWrite""#,
        r#""migration_extra""#,
        r#""unknown""#,
    ] {
        let parsed = serde_json::from_str::<LeasePurpose>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case Display tokens are canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CBOR round-trip preserves variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_every_purpose_variant() {
    for (variant, _) in ALL_PURPOSES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: LeasePurpose = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back, "CBOR round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Hash + Eq + Copy correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equal_purposes_hash_equally() {
    for (variant, _) in ALL_PURPOSES {
        let h1 = hash_of(variant);
        let h2 = hash_of(variant);
        assert_eq!(h1, h2, "Hash determinism for {variant:?}");
    }
}

#[test]
fn copy_preserves_equality_and_hash_for_lease_purpose() {
    for (variant, _) in ALL_PURPOSES {
        let copied: LeasePurpose = *variant; // Copy
        let cloned = copied; // Copy via assignment
        assert_eq!(*variant, copied);
        assert_eq!(*variant, cloned);
        assert_eq!(hash_of(variant), hash_of(&copied));
        assert_eq!(hash_of(variant), hash_of(&cloned));
    }
}

#[test]
fn lease_purpose_serves_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map: HashMap<LeasePurpose, &'static str> = HashMap::new();
    for (variant, token) in ALL_PURPOSES {
        map.insert(*variant, token);
    }
    assert_eq!(
        map.len(),
        ALL_PURPOSES.len(),
        "every variant a distinct key"
    );
    for (variant, token) in ALL_PURPOSES {
        assert_eq!(map.get(variant), Some(token));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Pairwise distinct variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn purpose_display_strings_are_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, token) in ALL_PURPOSES {
        assert!(seen.insert(*token), "duplicate Display token {token:?}");
    }
    assert_eq!(seen.len(), ALL_PURPOSES.len());
}

#[test]
fn purpose_variants_pairwise_unequal() {
    for i in 0..ALL_PURPOSES.len() {
        for j in (i + 1)..ALL_PURPOSES.len() {
            assert_ne!(
                ALL_PURPOSES[i].0, ALL_PURPOSES[j].0,
                "{:?} and {:?} MUST be distinct variants",
                ALL_PURPOSES[i].0, ALL_PURPOSES[j].0
            );
        }
    }
}

#[test]
fn distinct_purposes_hash_distinctly_in_practice() {
    let hashes: Vec<u64> = ALL_PURPOSES.iter().map(|(v, _)| hash_of(v)).collect();
    let unique: std::collections::HashSet<u64> = hashes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ALL_PURPOSES.len(),
        "6 variants MUST hash to distinct u64s in practice; got {hashes:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. LeaseId Display + FromStr round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_id_display_fromstr_roundtrip_bare_hex() {
    let original: LeaseId = ObjectId::from_bytes([0x42; 32]);
    let display = original.to_string();
    // Display is 64 lowercase hex chars (no prefix).
    assert_eq!(display.len(), 64, "Display MUST be 64 hex chars");
    assert!(
        display
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Display MUST be all-lowercase hex: {display}"
    );

    let reparsed: LeaseId = display
        .parse()
        .expect("FromStr accepts bare hex Display output");
    assert_eq!(original, reparsed, "Display→FromStr lost identity");
}

#[test]
fn lease_id_display_fromstr_roundtrip_objectid_prefix() {
    let original: LeaseId = ObjectId::from_bytes([0x99; 32]);
    let prefixed = original.to_prefixed_string();
    assert!(
        prefixed.starts_with("objectid:"),
        "to_prefixed_string MUST emit `objectid:<hex>` — got {prefixed}"
    );
    let stripped = prefixed.strip_prefix("objectid:").unwrap();
    assert_eq!(stripped.len(), 64, "prefixed form has 64-char hex suffix");

    // Both bare-hex and prefixed forms parse via FromStr (== parse_prefixed).
    let from_prefixed = LeaseId::from_str(&prefixed).expect("FromStr accepts prefixed");
    let from_bare = LeaseId::from_str(stripped).expect("FromStr accepts bare hex");
    assert_eq!(from_prefixed, original);
    assert_eq!(from_bare, original);
    assert_eq!(from_prefixed, from_bare);
}

#[test]
fn lease_id_display_is_deterministic() {
    let id: LeaseId = ObjectId::from_bytes([0xAB; 32]);
    let a = id.to_string();
    let b = id.to_string();
    assert_eq!(a, b, "Display MUST be deterministic");
    assert_eq!(a, "ab".repeat(32), "lowercase hex of [0xAB; 32]");
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. LeaseId parse rejects malformed input
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_id_fromstr_rejects_malformed_inputs() {
    // Non-hex chars.
    assert!(LeaseId::from_str("not-hex").is_err());
    // Wrong length (too short).
    assert!(LeaseId::from_str("ab").is_err());
    // Wrong length (too long).
    assert!(LeaseId::from_str(&"ab".repeat(33)).is_err());
    // Empty.
    assert!(LeaseId::from_str("").is_err());
    // 63 hex chars (odd length — hex::decode fails).
    assert!(LeaseId::from_str(&"a".repeat(63)).is_err());
}

#[test]
fn lease_id_fromstr_strips_only_objectid_prefix() {
    // The prefix-stripping is exact-match on `objectid:`, not a
    // generic prefix tolerance. Any other prefix is rejected.
    let id_hex = "ab".repeat(32);
    assert!(LeaseId::from_str(&format!("ObjectId:{id_hex}")).is_err());
    assert!(LeaseId::from_str(&format!("objectid::{id_hex}")).is_err());
    assert!(LeaseId::from_str(&format!("0x{id_hex}")).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. to_prefixed_string round-trips with FromStr
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn to_prefixed_string_canonical_roundtrip() {
    for seed in [0x00_u8, 0x01, 0x55, 0xAA, 0xFE, 0xFF] {
        let id: LeaseId = ObjectId::from_bytes([seed; 32]);
        let prefixed = id.to_prefixed_string();
        let back = LeaseId::from_str(&prefixed).expect("round-trip");
        assert_eq!(
            id, back,
            "prefixed-form round-trip lost identity for seed {seed:#x}"
        );
    }
}
