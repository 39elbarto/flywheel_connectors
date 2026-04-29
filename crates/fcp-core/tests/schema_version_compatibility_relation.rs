//! Pin `ManifestVersion::is_compatible_with` relation properties +
//! serde / Display / FromStr round-trip (flywheel_connectors-3xfmr).
//!
//! Bead asks for "SchemaVersion compatibility check across major
//! boundaries". No type literally named `SchemaVersion` exists in
//! fcp-core. The compatibility relation is on `ManifestVersion`
//! (connector_artifacts.rs:17, also re-exported as `ConnectorVersion`)
//! via `is_compatible_with`. Existing
//! `tests/manifest_version_compatibility.rs` already pins the broad
//! same-major / cross-major / pre-release / sort behavior. This test
//! pins the GAPS in the compatibility-relation contract — properties
//! that operators and registry/install code reason about but that
//! the prior test does not assert directly:
//!
//!   1. **Reflexivity** — every version is compatible with itself.
//!   2. **Major-boundary asymmetry** — compatibility is NOT
//!      symmetric in general; `1.2.0.is_compatible_with(1.0.0)` is
//!      true but the reverse is false (lower-than-required).
//!   3. **Patch + minor downgrade rejection** within the same major.
//!   4. **`0.x` major-zero quirk** — `is_compatible_with` only checks
//!      `major` equality, so `0.2.0` and `0.3.0` are mutually
//!      compatible by this rule even though semver itself treats
//!      every 0.x minor bump as breaking. Pin that explicit choice.
//!   5. **Build metadata participates in `semver` crate ordering**
//!      (contrary to the semver SPEC which says it MUST be ignored).
//!      Pin the reality so any future swap to a spec-compliant
//!      comparator fails this test deliberately.
//!   6. **Display agrees with semver Display**.
//!   7. **FromStr ⇄ Display round-trip** preserves equality.
//!   8. **Serde JSON is transparent** — `#[serde(transparent)]` so
//!      JSON form is the bare quoted semver string.
//!   9. **Serde CBOR round-trip** preserves equality.
//!  10. **Hash-Eq contract** across construction paths
//!      (`parse`, `FromStr`, `From<Version>`).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use fcp_core::ConnectorVersion;
use semver::Version;

fn v(input: &str) -> ConnectorVersion {
    input
        .parse()
        .unwrap_or_else(|err| panic!("parse {input}: {err}"))
}

fn hash_of<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Reflexivity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn is_compatible_with_is_reflexive() {
    for version in [
        "0.0.0",
        "0.1.0",
        "0.99.99",
        "1.0.0",
        "1.2.3",
        "2.0.0-alpha.1",
        "3.4.5+build.1",
        "10.20.30",
    ] {
        let parsed = v(version);
        assert!(
            parsed.is_compatible_with(&parsed),
            "is_compatible_with MUST be reflexive — {version} fails self-compat"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Major-boundary asymmetry
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn compat_relation_is_asymmetric_within_same_major() {
    // Higher-or-equal version is compat with required; the reverse
    // is NOT — a registry must not silently accept a lower binary
    // than a manifest demands.
    let pairs = [
        ("1.2.0", "1.0.0"), // newer.is_compatible_with(older) == true
        ("1.0.1", "1.0.0"),
        ("1.99.99", "1.0.0"),
        ("1.0.0", "1.0.0-rc.1"), // stable satisfies prerelease req
    ];
    for (newer, older) in pairs {
        let n = v(newer);
        let o = v(older);
        assert!(
            n.is_compatible_with(&o),
            "{newer} MUST satisfy required {older}"
        );
        assert!(
            !o.is_compatible_with(&n),
            "{older} MUST NOT satisfy higher required {newer} \
             (asymmetry pinning prevents silent downgrade)"
        );
    }
}

#[test]
fn compat_across_major_boundary_is_false_in_both_directions() {
    // The major check is exact — 1.x and 2.x are NEVER compat
    // either way.
    let pairs = [
        ("1.0.0", "2.0.0"),
        ("1.99.99", "2.0.0"),
        ("0.99.0", "1.0.0"),
        ("3.0.0", "2.99.99"),
    ];
    for (a, b) in pairs {
        let a_v = v(a);
        let b_v = v(b);
        assert!(
            !a_v.is_compatible_with(&b_v),
            "{a} MUST NOT satisfy {b} (major boundary)"
        );
        assert!(
            !b_v.is_compatible_with(&a_v),
            "{b} MUST NOT satisfy {a} (major boundary)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Patch + minor downgrade rejection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn patch_downgrade_rejected_within_same_major() {
    let required = v("1.2.3");
    for candidate in ["1.2.2", "1.2.0", "1.2.1"] {
        assert!(
            !v(candidate).is_compatible_with(&required),
            "patch downgrade {candidate} MUST NOT satisfy {required}"
        );
    }
}

#[test]
fn minor_downgrade_rejected_within_same_major() {
    let required = v("1.5.0");
    for candidate in ["1.4.99", "1.0.0", "1.1.999"] {
        assert!(
            !v(candidate).is_compatible_with(&required),
            "minor downgrade {candidate} MUST NOT satisfy {required}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. 0.x major-zero quirk
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn major_zero_is_compatible_within_zero_major() {
    // Document the explicit choice: `is_compatible_with` only
    // requires `major` equality, so 0.x minor bumps are considered
    // compatible by this relation even though plain semver would
    // treat them as breaking. Whoever depends on "0.x means every
    // bump is breaking" must encode that elsewhere — this test
    // pins what the relation actually does today so behavior change
    // is intentional.
    let required = v("0.1.0");
    for candidate in ["0.1.0", "0.1.99", "0.2.0", "0.99.99"] {
        let c = v(candidate);
        assert!(
            c.is_compatible_with(&required),
            "0.x relation: {candidate} MUST be compatible with {required} \
             (only major equality + non-downgrade is checked)"
        );
    }
    // Cross-zero-to-1 still rejected.
    assert!(!v("1.0.0").is_compatible_with(&required));
    assert!(!required.is_compatible_with(&v("1.0.0")));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Build metadata is ignored by ordering and compatibility
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn build_metadata_orders_lexicographically_in_semver_crate() {
    // The semver SPEC says build metadata MUST be ignored when
    // determining version precedence. The `semver` crate v1
    // implementation does NOT follow that — it orders build
    // metadata as a string tiebreaker. `is_compatible_with`
    // delegates to `cmp`, so the deviation flows through.
    //
    // Pin the actual behavior so a future swap to a spec-compliant
    // comparator fails this test deliberately, surfacing the
    // observable change to operators and registry tooling.
    let a = v("1.2.3+build.alpha");
    let b = v("1.2.3+build.beta");
    let plain = v("1.2.3");

    // Lexicographic ordering of build metadata: alpha < beta.
    assert!(
        b.is_compatible_with(&a),
        "newer build (beta) MUST satisfy older (alpha)"
    );
    assert!(
        !a.is_compatible_with(&b),
        "older build (alpha) MUST NOT satisfy newer (beta) — pinned downgrade rejection"
    );

    // Plain `1.2.3` is treated as LESS than any `1.2.3+build.*`
    // because the build-suffixed form has more characters. Pin
    // this surprising ordering so the contract is explicit.
    assert!(
        a.is_compatible_with(&plain),
        "1.2.3+build.alpha MUST satisfy plain 1.2.3 (semver crate orders +build > plain)"
    );
    assert!(
        !plain.is_compatible_with(&a),
        "plain 1.2.3 MUST NOT satisfy 1.2.3+build.alpha — plain is treated as lower"
    );

    // Reflexivity still holds for build-suffixed versions.
    assert!(a.is_compatible_with(&a));
    assert!(b.is_compatible_with(&b));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Display agrees with semver Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_matches_underlying_semver_display() {
    for s in [
        "0.0.0",
        "1.0.0",
        "1.2.3",
        "1.2.3-alpha.1",
        "1.2.3-rc.1+build.42",
        "10.20.30",
    ] {
        let parsed = v(s);
        assert_eq!(
            parsed.to_string(),
            Version::parse(s).unwrap().to_string(),
            "ManifestVersion Display MUST match semver Display for {s}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. FromStr ⇄ Display round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn from_str_display_roundtrip_preserves_equality() {
    for s in [
        "0.0.0",
        "1.2.3",
        "1.2.3-alpha.1",
        "1.2.3-rc.1+build.42",
        "99.99.99",
    ] {
        let original = v(s);
        let displayed = original.to_string();
        let reparsed: ConnectorVersion = displayed.parse().expect("reparse");
        assert_eq!(original, reparsed, "Display→FromStr lost equality for {s}");
        assert_eq!(
            hash_of(&original),
            hash_of(&reparsed),
            "Display→FromStr lost hash for {s}"
        );
    }
}

#[test]
fn parse_rejects_non_semver_strings() {
    for bad in ["", "abc", "1", "1.2", "1.2.3.4", "v1.2.3", "1.x.0"] {
        let parsed: Result<ConnectorVersion, _> = bad.parse();
        assert!(
            parsed.is_err(),
            "FromStr MUST reject non-semver input {bad:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Serde JSON transparent shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_form_is_transparent_bare_semver_string() {
    // `#[serde(transparent)]` on the newtype — the JSON form is the
    // quoted semver string, NOT a wrapping object.
    let cases = ["0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3-rc.1+build.42"];
    for s in cases {
        let parsed = v(s);
        let json = serde_json::to_string(&parsed).expect("serialize");
        assert_eq!(
            json,
            format!("\"{s}\""),
            "JSON form MUST be transparent bare semver string for {s}"
        );
        let back: ConnectorVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, back, "JSON round-trip lost {s}");
    }
}

#[test]
fn json_rejects_object_wrapping() {
    // Transparent serde MUST reject the non-transparent shape.
    let bad = serde_json::from_str::<ConnectorVersion>(r#"{"version":"1.2.3"}"#);
    assert!(bad.is_err(), "object-wrapped form MUST be rejected");

    let bad_array = serde_json::from_str::<ConnectorVersion>(r#"["1.2.3"]"#);
    assert!(bad_array.is_err(), "array-wrapped form MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_equality_and_hash() {
    for s in [
        "0.0.0",
        "1.2.3",
        "1.2.3-alpha.1",
        "1.2.3-rc.1+build.42",
        "10.20.30",
    ] {
        let original = v(s);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&original, &mut buf).expect("encode");
        let back: ConnectorVersion = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(original, back, "CBOR round-trip lost {s}");
        assert_eq!(hash_of(&original), hash_of(&back));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Hash-Eq contract across construction paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hash_eq_consistent_across_construction_paths() {
    let cases = ["0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3+build.42"];
    for s in cases {
        let via_parse: ConnectorVersion = ConnectorVersion::parse(s).unwrap();
        let via_from_str: ConnectorVersion = s.parse().unwrap();
        let via_from_version: ConnectorVersion = Version::parse(s).unwrap().into();
        let via_clone = via_parse.clone();
        let via_json: ConnectorVersion =
            serde_json::from_str(&serde_json::to_string(&via_parse).unwrap()).unwrap();

        for other in [&via_from_str, &via_from_version, &via_clone, &via_json] {
            assert_eq!(via_parse, *other, "{s}: equality across construction paths");
            assert_eq!(
                hash_of(&via_parse),
                hash_of(other),
                "{s}: hash across construction paths"
            );
        }
    }
}

#[test]
fn distinct_versions_pairwise_unequal() {
    let versions: Vec<ConnectorVersion> = [
        "0.0.0",
        "0.0.1",
        "0.1.0",
        "1.0.0",
        "1.0.0-rc.1",
        "1.0.0-rc.2",
        "1.0.1",
        "1.1.0",
        "2.0.0",
    ]
    .iter()
    .map(|s| v(s))
    .collect();
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            assert_ne!(
                versions[i], versions[j],
                "{:?} and {:?} MUST be distinct",
                versions[i], versions[j]
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Identical pre-release strings are mutually compatible
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn identical_prerelease_strings_are_mutually_compatible() {
    // Pin that the prerelease comparison is exact-equality-based for
    // the equal case (no surprising "newer-rc-because-string-sort"
    // behavior on identical inputs).
    let a = v("1.0.0-rc.1");
    let b = v("1.0.0-rc.1");
    assert!(a.is_compatible_with(&b));
    assert!(b.is_compatible_with(&a));
    assert_eq!(a, b);
    assert_eq!(hash_of(&a), hash_of(&b));
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. From<ConnectorVersion> for Version (round-trip via inner Version)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn round_trip_through_inner_version_preserves_equality() {
    for s in ["1.2.3", "1.2.3-alpha.1", "1.2.3+build.42"] {
        let original = v(s);
        let inner: Version = original.clone().into();
        let back: ConnectorVersion = inner.into();
        assert_eq!(original, back);
        assert_eq!(hash_of(&original), hash_of(&back));
    }
}
