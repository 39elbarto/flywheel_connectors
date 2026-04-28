//! Pin `SchemaId` hash + canonical-form stability
//! (flywheel_connectors-sbget).
//!
//! `SchemaId` is the structural type-discriminator that sits inside
//! every canonical CBOR payload, every `ObjectId` derivation, and
//! every signing transcript that needs to distinguish "AuditEvent"
//! from "RevocationEvent". Drift in any of its hash or canonical-form
//! semantics fragments content addressing across implementations.
//!
//! Bead asks for "Display+FromStr roundtrip stability". `SchemaId`
//! does NOT implement `Display` or `FromStr`; the canonical string
//! form is produced by `as_bytes()` (returning `Vec<u8>` of
//! `{namespace}:{name}@{version}`). Tests pin what exists:
//!
//!   1. **Hash-trait determinism** — `DefaultHasher` agrees with
//!      itself on the same `SchemaId`; equal `SchemaId`s hash
//!      identically (the `Hash` + `Eq` contract).
//!   2. **`as_bytes()` canonical form** — exact byte format
//!      `"{namespace}:{name}@{version}"` and stability under
//!      repeated calls.
//!   3. **`hash()` SchemaHash determinism** — BLAKE3-based, fixed
//!      32 bytes, deterministic.
//!   4. **`hash()` injectivity** — the length-prefixed encoding
//!      defeats the historical collision class
//!      `("a:b", "c") vs ("a", "b:c")`. The constructor rejects
//!      those inputs, but the test still verifies that two
//!      `SchemaId`s built via the public-fields path with reserved
//!      separators in different positions produce DIFFERENT hashes.
//!   5. **`try_new` rejects reserved separators** in namespace and
//!      name, with the offending character carried in the error.
//!   6. **Cross-version distinctness** — same namespace+name but
//!      different version produces a different hash.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use fcp_cbor::{SCHEMA_HASH_LEN, SchemaHash, SchemaId, SchemaIdError};
use semver::Version;

fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Hash-trait determinism + equal-implies-same-hash
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_id_hash_trait_deterministic() {
    let s = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let h1 = hash_of(&s);
    let h2 = hash_of(&s);
    let h3 = hash_of(&s);
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

#[test]
fn schema_id_equal_values_hash_identically() {
    // Two SchemaIds constructed via different paths but same content
    // MUST hash to the same DefaultHasher u64.
    let via_new = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let via_try_new = SchemaId::try_new("fcp.core", "AuditEvent", Version::new(1, 0, 0))
        .expect("try_new on canonical input");
    let via_struct_literal = SchemaId {
        namespace: "fcp.core".to_string(),
        name: "AuditEvent".to_string(),
        version: Version::new(1, 0, 0),
    };
    let via_clone = via_new.clone();

    assert_eq!(via_new, via_try_new);
    assert_eq!(via_new, via_struct_literal);
    assert_eq!(via_new, via_clone);

    let h_new = hash_of(&via_new);
    assert_eq!(h_new, hash_of(&via_try_new));
    assert_eq!(h_new, hash_of(&via_struct_literal));
    assert_eq!(h_new, hash_of(&via_clone));
}

#[test]
fn schema_id_distinct_values_hash_distinctly_in_practice() {
    // The Hash contract does NOT require collisions to be impossible,
    // but on these documented schemas we expect distinct values to
    // hash differently — a sanity check on the hasher producing
    // useful output.
    let cases = [
        SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0)),
        SchemaId::new("fcp.core", "RevocationEvent", Version::new(1, 0, 0)),
        SchemaId::new("fcp.core", "ZoneCheckpoint", Version::new(1, 0, 0)),
        SchemaId::new("fcp.mesh", "GossipSummary", Version::new(1, 0, 0)),
        SchemaId::new("fcp.connector", "InvokeRequest", Version::new(1, 0, 0)),
    ];
    let hashes: Vec<u64> = cases.iter().map(hash_of).collect();
    let unique: std::collections::HashSet<u64> = hashes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        cases.len(),
        "expected canonical schemas to hash to distinct u64 values; got {hashes:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. as_bytes() canonical form
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_id_canonical_form_exact_format() {
    let s = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let bytes = s.as_bytes();
    let canonical = String::from_utf8(bytes).expect("UTF-8");
    assert_eq!(
        canonical, "fcp.core:AuditEvent@1.0.0",
        "as_bytes MUST format as `{{namespace}}:{{name}}@{{version}}`"
    );
}

#[test]
fn schema_id_canonical_form_with_prerelease() {
    let s = SchemaId::new(
        "fcp.core",
        "AuditEvent",
        Version::parse("1.0.0-rc.1").unwrap(),
    );
    let canonical = String::from_utf8(s.as_bytes()).unwrap();
    assert_eq!(canonical, "fcp.core:AuditEvent@1.0.0-rc.1");
}

#[test]
fn schema_id_canonical_form_deterministic() {
    let s = SchemaId::new("fcp.mesh", "GossipSummary", Version::new(2, 1, 3));
    let a = s.as_bytes();
    let b = s.as_bytes();
    let c = s.as_bytes();
    assert_eq!(a, b);
    assert_eq!(b, c);
    assert_eq!(
        String::from_utf8(a).unwrap(),
        "fcp.mesh:GossipSummary@2.1.3"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. SchemaHash determinism + length
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_hash_is_deterministic() {
    let s = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let h1 = s.hash();
    let h2 = s.hash();
    let h3 = s.hash();
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
    assert_eq!(h1.as_bytes().len(), SCHEMA_HASH_LEN);
    assert_eq!(SCHEMA_HASH_LEN, 32, "SCHEMA_HASH_LEN drift — expected 32");
}

#[test]
fn schema_hash_distinct_schemas_distinct_hashes() {
    let h_audit = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0)).hash();
    let h_rev = SchemaId::new("fcp.core", "RevocationEvent", Version::new(1, 0, 0)).hash();
    let h_chk = SchemaId::new("fcp.core", "ZoneCheckpoint", Version::new(1, 0, 0)).hash();
    assert_ne!(h_audit, h_rev);
    assert_ne!(h_audit, h_chk);
    assert_ne!(h_rev, h_chk);
}

#[test]
fn schema_hash_display_is_lowercase_hex() {
    let s = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let h = s.hash();
    let display = format!("{h}");
    assert_eq!(display.len(), 64, "Display MUST be 64 hex chars (32 bytes)");
    assert!(
        display
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Display MUST be lowercase hex: {display}"
    );
}

#[test]
fn schema_hash_from_bytes_round_trip() {
    let s = SchemaId::new("fcp.core", "ZoneCheckpoint", Version::new(1, 2, 3));
    let h = s.hash();
    let rebuilt = SchemaHash::from_bytes(*h.as_bytes());
    assert_eq!(h, rebuilt);
    assert_eq!(format!("{h}"), format!("{rebuilt}"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SchemaHash injectivity / length-prefix collision resistance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_hash_resists_separator_split_collision() {
    // Historical risk: encoding `namespace || ':' || name || '@' ||
    // version` would collide for `(a:b, c)` vs `(a, b:c)`. The
    // public constructor REJECTS these inputs (try_new fails with
    // ReservedSeparator), but if a SchemaId is built via the public
    // struct-literal path, the reserved separators reach `hash()`.
    // Verify the length-prefixed encoding distinguishes the two
    // forms anyway.
    let bypass_left = SchemaId {
        namespace: "a:b".to_string(),
        name: "c".to_string(),
        version: Version::new(1, 0, 0),
    };
    let bypass_right = SchemaId {
        namespace: "a".to_string(),
        name: "b:c".to_string(),
        version: Version::new(1, 0, 0),
    };
    assert_ne!(
        bypass_left.hash(),
        bypass_right.hash(),
        "INJECTIVITY REGRESSION: length-prefixed schema-hash encoding must distinguish \
         (a:b, c) from (a, b:c) — historical collision class lib.rs:117-121"
    );
}

#[test]
fn schema_hash_resists_at_split_collision() {
    // Same idea but with `@` (the version separator). `("a@b", "c")`
    // and `("a", "b", version=...)` could collide under a naive
    // concat encoding.
    let bypass_left = SchemaId {
        namespace: "a@b".to_string(),
        name: "c".to_string(),
        version: Version::new(1, 0, 0),
    };
    let bypass_right = SchemaId {
        namespace: "a".to_string(),
        name: "b@c".to_string(),
        version: Version::new(1, 0, 0),
    };
    assert_ne!(
        bypass_left.hash(),
        bypass_right.hash(),
        "INJECTIVITY REGRESSION: `@`-split schema-hash encoding must not collide"
    );
}

#[test]
fn schema_hash_distinguishes_empty_namespace_from_short_name() {
    // ("", "ab") vs ("a", "b"): the underlying bytes for the
    // namespace+name segment are the same character sequence, so a
    // non-length-prefixed encoding could collide. Length-prefixing
    // MUST distinguish them.
    let a = SchemaId {
        namespace: "".to_string(),
        name: "ab".to_string(),
        version: Version::new(1, 0, 0),
    };
    let b = SchemaId {
        namespace: "a".to_string(),
        name: "b".to_string(),
        version: Version::new(1, 0, 0),
    };
    assert_ne!(
        a.hash(),
        b.hash(),
        "length-prefixed encoding MUST distinguish ('', 'ab') from ('a', 'b')"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Reserved-separator rejection in try_new
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_id_try_new_rejects_colon_in_namespace() {
    let err = SchemaId::try_new("fcp:core", "AuditEvent", Version::new(1, 0, 0))
        .expect_err("`:` in namespace MUST be rejected");
    match err {
        SchemaIdError::ReservedSeparator { field, separator } => {
            assert_eq!(field, "namespace");
            assert_eq!(separator, ':');
        }
    }
}

#[test]
fn schema_id_try_new_rejects_at_in_namespace() {
    let err = SchemaId::try_new("fcp@core", "AuditEvent", Version::new(1, 0, 0))
        .expect_err("`@` in namespace MUST be rejected");
    match err {
        SchemaIdError::ReservedSeparator { field, separator } => {
            assert_eq!(field, "namespace");
            assert_eq!(separator, '@');
        }
    }
}

#[test]
fn schema_id_try_new_rejects_colon_in_name() {
    let err = SchemaId::try_new("fcp.core", "Audit:Event", Version::new(1, 0, 0))
        .expect_err("`:` in name MUST be rejected");
    match err {
        SchemaIdError::ReservedSeparator { field, separator } => {
            assert_eq!(field, "name");
            assert_eq!(separator, ':');
        }
    }
}

#[test]
fn schema_id_try_new_rejects_at_in_name() {
    let err = SchemaId::try_new("fcp.core", "Audit@Event", Version::new(1, 0, 0))
        .expect_err("`@` in name MUST be rejected");
    match err {
        SchemaIdError::ReservedSeparator { field, separator } => {
            assert_eq!(field, "name");
            assert_eq!(separator, '@');
        }
    }
}

#[test]
fn schema_id_new_panics_on_reserved_separator() {
    let result =
        std::panic::catch_unwind(|| SchemaId::new("fcp:core", "AuditEvent", Version::new(1, 0, 0)));
    assert!(
        result.is_err(),
        "SchemaId::new MUST panic on reserved separators (the documented behavior)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Cross-version distinctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_hash_distinguishes_versions() {
    let v1 = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0)).hash();
    let v2 = SchemaId::new("fcp.core", "AuditEvent", Version::new(2, 0, 0)).hash();
    let v110 = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 1, 0)).hash();
    let v101 = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 1)).hash();
    let v100_rc1 = SchemaId::new(
        "fcp.core",
        "AuditEvent",
        Version::parse("1.0.0-rc.1").unwrap(),
    )
    .hash();

    assert_ne!(v1, v2);
    assert_ne!(v1, v110);
    assert_ne!(v1, v101);
    assert_ne!(v1, v100_rc1, "1.0.0 and 1.0.0-rc.1 MUST hash differently");
}

#[test]
fn schema_id_canonical_form_distinguishes_versions() {
    // Same as_bytes() format pinning across versions.
    let cases = [
        (Version::new(1, 0, 0), "fcp.core:AuditEvent@1.0.0"),
        (Version::new(2, 5, 9), "fcp.core:AuditEvent@2.5.9"),
        (
            Version::parse("1.0.0-rc.1").unwrap(),
            "fcp.core:AuditEvent@1.0.0-rc.1",
        ),
        (
            Version::parse("1.0.0+build.42").unwrap(),
            "fcp.core:AuditEvent@1.0.0+build.42",
        ),
    ];
    for (version, expected) in cases {
        let s = SchemaId::new("fcp.core", "AuditEvent", version);
        assert_eq!(String::from_utf8(s.as_bytes()).unwrap(), expected);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. HashMap-key correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn schema_id_serves_as_hashmap_key_correctly() {
    use std::collections::HashMap;
    let mut map: HashMap<SchemaId, &'static str> = HashMap::new();
    let key_a = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let key_b = SchemaId::new("fcp.core", "RevocationEvent", Version::new(1, 0, 0));
    map.insert(key_a.clone(), "audit");
    map.insert(key_b.clone(), "revocation");

    // Look up via fresh constructions — Hash-Eq contract MUST find
    // them.
    let lookup_a = SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0));
    let lookup_b = SchemaId::new("fcp.core", "RevocationEvent", Version::new(1, 0, 0));
    assert_eq!(map.get(&lookup_a), Some(&"audit"));
    assert_eq!(map.get(&lookup_b), Some(&"revocation"));
    assert_eq!(map.len(), 2);
}
