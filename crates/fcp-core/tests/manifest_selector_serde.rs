//! Pin `ConnectorTarget` JSON+CBOR shape + `ManifestVersion::is_compatible_with`
//! selector truth table — the closest analogue to "ManifestSelector serde"
//! (flywheel_connectors-46kt1).
//!
//! Bead asks for `ManifestSelector` JSON+CBOR roundtrip pinning. No type
//! literally named `ManifestSelector` exists in fcp-core. Manifest selection
//! is performed by [`RegistryEntry`] keys (id + version + target), and the
//! per-axis selector shapes are:
//!   * [`ConnectorTarget`] at `crates/fcp-core/src/connector_artifacts.rs:81`
//!     — the os+arch axis,
//!   * [`ManifestVersion`] at `crates/fcp-core/src/connector_artifacts.rs:19`
//!     — the version axis with `is_compatible_with` selector predicate
//!     (stricter than plain semver ordering).
//!
//! Existing `connector_bundle_serde_extended.rs` covers RegistryEntry full
//! shape + roundtrip and ConnectorTarget Display via the bundle. This pin
//! adds the residual axes:
//!   * ConnectorTarget standalone JSON + CBOR shape per os/arch combo,
//!   * ConnectorTarget::as_string() format pinning,
//!   * ConnectorTarget::from_env() returns a non-empty pair,
//!   * ManifestVersion #[serde(transparent)] scalar form,
//!   * ManifestVersion Display + FromStr fixed point,
//!   * `is_compatible_with` selector truth table:
//!     same-major, equal/higher → compatible; lower → NOT compatible;
//!     different-major → NEVER compatible (the loud cross-major sentinel),
//!   * ManifestVersion Ord matches semver ordering,
//!   * ConnectorVersion alias points to ManifestVersion.

use ciborium::Value as CborValue;
use fcp_core::{ConnectorTarget, ConnectorVersion, ManifestVersion};
use serde_json::json;

fn target(os: &str, arch: &str) -> ConnectorTarget {
    ConnectorTarget {
        os: os.to_string(),
        arch: arch.to_string(),
    }
}

fn ver(s: &str) -> ManifestVersion {
    ManifestVersion::parse(s).unwrap()
}

#[test]
fn connector_target_json_shape_pins_os_and_arch_fields() {
    let t = target("linux", "amd64");
    let v = serde_json::to_value(&t).unwrap();
    let obj = v.as_object().expect("must be object");
    assert_eq!(obj.len(), 2, "ConnectorTarget shape drift: {obj:?}");
    assert_eq!(obj.get("os"), Some(&json!("linux")));
    assert_eq!(obj.get("arch"), Some(&json!("amd64")));

    let back: ConnectorTarget = serde_json::from_value(v).unwrap();
    assert_eq!(back, t);
}

#[test]
fn connector_target_json_roundtrip_for_diverse_os_arch_combos() {
    let cases = [
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("macos", "arm64"),
        ("macos", "amd64"),
        ("windows", "amd64"),
        ("freebsd", "riscv64"),
    ];
    for (os, arch) in cases {
        let t = target(os, arch);
        let bytes = serde_json::to_vec(&t).unwrap();
        let back: ConnectorTarget = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.os, os);
        assert_eq!(back.arch, arch);
    }
}

#[test]
fn connector_target_cbor_roundtrip_preserves_fields() {
    let t = target("macos", "arm64");
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&t, &mut bytes).unwrap();
    let back: ConnectorTarget = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back, t);

    // CBOR shape: a 2-key Map of Text scalars.
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("expected Map, got {other:?}"),
    };
    assert_eq!(map.len(), 2, "ConnectorTarget CBOR shape drift");
}

#[test]
fn connector_target_as_string_format_pinned() {
    assert_eq!(target("linux", "amd64").as_string(), "linux-amd64");
    assert_eq!(target("macos", "arm64").as_string(), "macos-arm64");
    assert_eq!(target("windows", "amd64").as_string(), "windows-amd64");
}

#[test]
fn connector_target_from_env_returns_non_empty_pair() {
    let t = ConnectorTarget::from_env();
    assert!(!t.os.is_empty(), "from_env os must not be empty");
    assert!(!t.arch.is_empty(), "from_env arch must not be empty");
    // The arch normalization maps x86_64 → amd64 and aarch64 → arm64.
    assert!(
        t.arch != "x86_64" && t.arch != "aarch64",
        "from_env must normalize x86_64/aarch64 → amd64/arm64, got `{}`",
        t.arch
    );
}

#[test]
fn distinct_targets_serialize_distinctly() {
    let a = target("linux", "amd64");
    let b = target("linux", "arm64");
    let c = target("macos", "amd64");
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    let cv = serde_json::to_value(&c).unwrap();
    assert_ne!(av, bv);
    assert_ne!(av, cv);
    assert_ne!(bv, cv);
}

#[test]
fn connector_target_works_as_hashmap_key() {
    let mut counts: std::collections::HashMap<ConnectorTarget, u32> =
        std::collections::HashMap::new();
    *counts.entry(target("linux", "amd64")).or_insert(0) += 2;
    *counts.entry(target("macos", "arm64")).or_insert(0) += 1;
    *counts.entry(target("linux", "amd64")).or_insert(0) += 1;
    assert_eq!(counts.get(&target("linux", "amd64")), Some(&3));
    assert_eq!(counts.get(&target("macos", "arm64")), Some(&1));
    assert_eq!(counts.get(&target("windows", "amd64")), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// ManifestVersion serde + selector predicate
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manifest_version_serde_is_transparent_scalar_string() {
    // #[serde(transparent)] → forwards to the inner Version, which serializes
    // as a bare semver string scalar.
    let mv = ver("1.2.3");
    let v = serde_json::to_value(&mv).unwrap();
    assert_eq!(v, json!("1.2.3"), "ManifestVersion JSON drift: {v:?}");

    let back: ManifestVersion = serde_json::from_value(v).unwrap();
    assert_eq!(back, mv);
}

#[test]
fn manifest_version_display_matches_semver_string_form() {
    assert_eq!(ver("1.2.3").to_string(), "1.2.3");
    assert_eq!(ver("0.1.0").to_string(), "0.1.0");
    assert_eq!(ver("10.20.30-beta.1").to_string(), "10.20.30-beta.1");
}

#[test]
fn manifest_version_from_str_fixed_point() {
    let cases = ["0.1.0", "1.0.0", "2.5.0", "10.20.30-beta.1", "1.2.3+build.42"];
    for s in cases {
        let parsed: ManifestVersion = s.parse().unwrap();
        assert_eq!(parsed.to_string(), s);
    }
}

#[test]
fn manifest_version_cbor_roundtrip() {
    let mv = ver("3.1.4-rc.2");
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&mv, &mut bytes).unwrap();
    let back: ManifestVersion = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back, mv);

    // CBOR transparent → Text scalar of the semver string.
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    match value {
        CborValue::Text(t) => assert_eq!(t, "3.1.4-rc.2"),
        other => panic!("ManifestVersion must encode as CBOR Text, got {other:?}"),
    }
}

#[test]
fn is_compatible_with_same_version_is_compatible() {
    let v = ver("1.2.3");
    assert!(v.is_compatible_with(&v));
}

#[test]
fn is_compatible_with_same_major_higher_is_compatible() {
    // Same-major forward evolution: candidate >= required.
    assert!(ver("1.2.3").is_compatible_with(&ver("1.2.0")));
    assert!(ver("1.5.0").is_compatible_with(&ver("1.2.3")));
    assert!(ver("1.10.0").is_compatible_with(&ver("1.2.3")));
}

#[test]
fn is_compatible_with_same_major_lower_is_not_compatible() {
    // Same-major regression: candidate < required.
    assert!(!ver("1.2.0").is_compatible_with(&ver("1.2.3")));
    assert!(!ver("1.0.0").is_compatible_with(&ver("1.5.0")));
    assert!(!ver("1.1.99").is_compatible_with(&ver("1.2.0")));
}

#[test]
fn is_compatible_with_different_major_is_never_compatible() {
    // The loud cross-major sentinel: even if the candidate version is
    // numerically higher across a major bump, compatibility is rejected.
    // This is the documented rule: "stricter than plain semantic-version
    // ordering: the major version must match exactly".
    assert!(!ver("2.0.0").is_compatible_with(&ver("1.2.3")));
    assert!(!ver("0.9.9").is_compatible_with(&ver("1.0.0")));
    assert!(!ver("3.5.0").is_compatible_with(&ver("2.5.0")));
    // Forward across major: still rejected even though strictly higher.
    assert!(!ver("10.0.0").is_compatible_with(&ver("9.99.99")));
}

#[test]
fn is_compatible_with_zero_major_pre_release_handling() {
    // 0.x is its own major; same-zero-major + higher minor is compatible.
    assert!(ver("0.5.0").is_compatible_with(&ver("0.1.0")));
    assert!(!ver("0.1.0").is_compatible_with(&ver("0.5.0")));
}

#[test]
fn manifest_version_ord_matches_semver_ordering() {
    let mut versions = vec![
        ver("2.0.0"),
        ver("1.0.0"),
        ver("1.10.0"),
        ver("1.2.0"),
        ver("0.5.0"),
    ];
    versions.sort();
    let sorted_strings: Vec<String> = versions.iter().map(ToString::to_string).collect();
    assert_eq!(
        sorted_strings,
        vec!["0.5.0", "1.0.0", "1.2.0", "1.10.0", "2.0.0"],
    );
}

#[test]
fn connector_version_is_alias_for_manifest_version() {
    // ConnectorVersion is a `pub type` alias for ManifestVersion. Pin via
    // assignment compatibility — if they ever diverge, this fails to type-check.
    let mv: ManifestVersion = ver("1.2.3");
    let cv: ConnectorVersion = mv.clone();
    assert_eq!(mv, cv);

    let back_mv: ManifestVersion = cv;
    assert_eq!(back_mv, ver("1.2.3"));
}

#[test]
fn distinct_versions_serialize_distinctly() {
    let cases = ["1.0.0", "1.0.1", "1.1.0", "2.0.0"];
    let mut seen = std::collections::HashSet::new();
    for s in cases {
        let v = serde_json::to_value(ver(s)).unwrap();
        assert!(seen.insert(v.clone()), "duplicate JSON: {v:?}");
    }
}

#[test]
fn invalid_semver_strings_fail_to_parse() {
    assert!(ManifestVersion::parse("").is_err());
    assert!(ManifestVersion::parse("abc").is_err());
    assert!(ManifestVersion::parse("1").is_err());
    assert!(ManifestVersion::parse("1.2").is_err());
    assert!(ManifestVersion::parse("1.2.3.4").is_err());
}
