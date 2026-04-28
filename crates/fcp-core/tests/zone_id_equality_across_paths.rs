//! Pin `ZoneId` equality + hash across every construction path
//! (flywheel_connectors-0j4qx).
//!
//! `ZoneId` is the most-touched identifier in fcp-core: every
//! `ObjectHeader`, `Provenance`, `CapabilityToken`, audit event, and
//! mesh frame carries one. Drift in any equality / hash semantics
//! between construction paths fragments content addressing and zone
//! membership at the boundary between layers.
//!
//! Construction paths exercised:
//!
//! - `ZoneId::owner()` / `private()` / `work()` / `community()` /
//!   `public()` — the five built-in factory methods.
//! - `ZoneId::try_from(String)` — the validating wire-deserialization
//!   path, also used by serde via `try_from = "String"`.
//! - `<&str>.parse::<ZoneId>()` — `FromStr` (delegates to `try_from`).
//! - `Display → FromStr` round-trip — the canonical "format and
//!    re-parse" pair.
//! - `clone` — Arc<str> bumping the refcount; equality/hash MUST
//!   match the original.
//! - `to_tailscale_tag → from_tailscale_tag` — the ZoneId-only
//!   round-trip through the Tailscale ACL tag namespace.
//!
//! Inequality is also pinned: distinct zones (`z:work` vs `z:public`
//! etc.) MUST be `!=` and hash to distinct values.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use fcp_core::ZoneId;

fn hash_of<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

const CANONICAL_ZONES: &[(&str, fn() -> ZoneId)] = &[
    ("z:owner", ZoneId::owner),
    ("z:private", ZoneId::private),
    ("z:work", ZoneId::work),
    ("z:community", ZoneId::community),
    ("z:public", ZoneId::public),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. Equality + hash across all construction paths for the canonical zones
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_zones_equal_across_construction_paths() {
    for (canonical, factory) in CANONICAL_ZONES {
        let via_factory = factory();
        let via_try_from = ZoneId::try_from((*canonical).to_string())
            .unwrap_or_else(|err| panic!("try_from({canonical}): {err}"));
        let via_parse = canonical
            .parse::<ZoneId>()
            .unwrap_or_else(|err| panic!("parse({canonical}): {err}"));
        let via_from_str =
            ZoneId::from_str(canonical).unwrap_or_else(|err| panic!("FromStr({canonical}): {err}"));
        let via_clone = via_factory.clone();
        let via_display_rt =
            ZoneId::try_from(via_factory.to_string()).expect("Display → try_from round-trip");

        // Equality.
        assert_eq!(
            via_factory, via_try_from,
            "{canonical}: factory vs try_from"
        );
        assert_eq!(via_factory, via_parse, "{canonical}: factory vs parse");
        assert_eq!(
            via_factory, via_from_str,
            "{canonical}: factory vs from_str"
        );
        assert_eq!(via_factory, via_clone, "{canonical}: clone");
        assert_eq!(
            via_factory, via_display_rt,
            "{canonical}: Display roundtrip"
        );

        // Hash.
        let h = hash_of(&via_factory);
        assert_eq!(h, hash_of(&via_try_from), "{canonical}: hash try_from");
        assert_eq!(h, hash_of(&via_parse), "{canonical}: hash parse");
        assert_eq!(h, hash_of(&via_from_str), "{canonical}: hash from_str");
        assert_eq!(h, hash_of(&via_clone), "{canonical}: hash clone");
        assert_eq!(h, hash_of(&via_display_rt), "{canonical}: hash Display rt");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Project subzone equality across construction paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn project_subzone_equal_across_construction_paths() {
    let canonical = "z:project:alpha-team";
    let via_try_from = ZoneId::try_from(canonical.to_string()).expect("try_from");
    let via_parse = canonical.parse::<ZoneId>().expect("parse");
    let via_from_str = ZoneId::from_str(canonical).expect("FromStr");
    let via_clone = via_try_from.clone();
    let via_display_rt = ZoneId::try_from(via_try_from.to_string()).expect("Display rt");

    assert_eq!(via_try_from, via_parse);
    assert_eq!(via_try_from, via_from_str);
    assert_eq!(via_try_from, via_clone);
    assert_eq!(via_try_from, via_display_rt);

    let h = hash_of(&via_try_from);
    assert_eq!(h, hash_of(&via_parse));
    assert_eq!(h, hash_of(&via_from_str));
    assert_eq!(h, hash_of(&via_clone));
    assert_eq!(h, hash_of(&via_display_rt));

    // as_str returns the canonical form verbatim.
    assert_eq!(via_try_from.as_str(), canonical);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Tailscale tag round-trip preserves equality + hash
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tailscale_tag_roundtrip_preserves_equality_for_canonical_zones() {
    for (canonical, factory) in CANONICAL_ZONES {
        let original = factory();
        let tag = original.to_tailscale_tag();
        let rebuilt = ZoneId::from_tailscale_tag(&tag)
            .unwrap_or_else(|err| panic!("from_tailscale_tag({tag}) for {canonical}: {err:?}"));
        assert_eq!(
            original, rebuilt,
            "{canonical}: Tailscale tag round-trip lost equality"
        );
        assert_eq!(
            hash_of(&original),
            hash_of(&rebuilt),
            "{canonical}: Tailscale tag round-trip lost hash"
        );
    }
}

#[test]
fn tailscale_tag_roundtrip_preserves_project_subzone() {
    let original = ZoneId::try_from("z:project:alpha-team".to_string()).expect("project zone");
    let tag = original.to_tailscale_tag();
    assert!(
        tag.starts_with("tag:fcp-proj-"),
        "project subzone MUST tag as `tag:fcp-proj-<name>`, got {tag}"
    );
    let rebuilt = ZoneId::from_tailscale_tag(&tag).expect("from_tailscale_tag");
    assert_eq!(
        original, rebuilt,
        "project subzone Tailscale tag round-trip lost equality"
    );
    assert_eq!(hash_of(&original), hash_of(&rebuilt));
}

#[test]
fn tailscale_tag_format_pinned_for_each_canonical_zone() {
    // Pin the exact tag form the Tailscale ACL layer expects.
    let cases = [
        (ZoneId::owner(), "tag:fcp-owner"),
        (ZoneId::private(), "tag:fcp-private"),
        (ZoneId::work(), "tag:fcp-work"),
        (ZoneId::community(), "tag:fcp-community"),
        (ZoneId::public(), "tag:fcp-public"),
    ];
    for (zone, expected_tag) in cases {
        assert_eq!(
            zone.to_tailscale_tag(),
            expected_tag,
            "to_tailscale_tag drift for {zone}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Inequality across distinct zones
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_canonical_zones_are_pairwise_unequal() {
    let zones: Vec<ZoneId> = CANONICAL_ZONES.iter().map(|(_, f)| f()).collect();
    for i in 0..zones.len() {
        for j in (i + 1)..zones.len() {
            assert_ne!(
                zones[i], zones[j],
                "{} and {} MUST be distinct ZoneIds",
                CANONICAL_ZONES[i].0, CANONICAL_ZONES[j].0
            );
        }
    }
}

#[test]
fn distinct_canonical_zones_hash_distinctly_in_practice() {
    // Hash contract permits collisions but on these documented zones
    // we expect distinct hashes — sanity check on the hasher.
    let zones: Vec<ZoneId> = CANONICAL_ZONES.iter().map(|(_, f)| f()).collect();
    let hashes: Vec<u64> = zones.iter().map(hash_of).collect();
    let unique: std::collections::HashSet<u64> = hashes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        zones.len(),
        "canonical zones MUST hash to distinct u64s in practice; got {hashes:?}"
    );
}

#[test]
fn project_subzones_with_different_names_are_distinct() {
    let alpha = ZoneId::try_from("z:project:alpha".to_string()).expect("alpha");
    let beta = ZoneId::try_from("z:project:beta".to_string()).expect("beta");
    assert_ne!(alpha, beta);
    assert_ne!(hash_of(&alpha), hash_of(&beta));
}

#[test]
fn canonical_zone_and_project_subzone_with_same_suffix_are_distinct() {
    // `z:work` and `z:project:work` are different zones — the
    // `project:` infix is part of identity.
    let work = ZoneId::work();
    let project_work = ZoneId::try_from("z:project:work".to_string()).expect("project work");
    assert_ne!(work, project_work);
    assert_ne!(hash_of(&work), hash_of(&project_work));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. HashMap-key correctness across construction paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_id_serves_as_hashmap_key_across_paths() {
    use std::collections::HashMap;
    let mut map: HashMap<ZoneId, &'static str> = HashMap::new();
    for (canonical, factory) in CANONICAL_ZONES {
        map.insert(factory(), canonical);
    }
    assert_eq!(map.len(), CANONICAL_ZONES.len());

    // Look up via every other construction path — Hash-Eq contract
    // MUST find each entry.
    for (canonical, _) in CANONICAL_ZONES {
        let lookup_via_try_from = ZoneId::try_from((*canonical).to_string()).unwrap();
        let lookup_via_parse = canonical.parse::<ZoneId>().unwrap();
        let lookup_via_tailscale = {
            // Round-trip through tag and back to test the tag path.
            let zone = canonical.parse::<ZoneId>().unwrap();
            let tag = zone.to_tailscale_tag();
            ZoneId::from_tailscale_tag(&tag).unwrap()
        };
        assert_eq!(
            map.get(&lookup_via_try_from),
            Some(canonical),
            "lookup via try_from for {canonical}"
        );
        assert_eq!(
            map.get(&lookup_via_parse),
            Some(canonical),
            "lookup via parse for {canonical}"
        );
        assert_eq!(
            map.get(&lookup_via_tailscale),
            Some(canonical),
            "lookup via Tailscale tag round-trip for {canonical}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. as_str / Display / as_bytes view consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn views_agree_for_each_canonical_zone() {
    for (canonical, factory) in CANONICAL_ZONES {
        let z = factory();
        assert_eq!(z.as_str(), *canonical, "{canonical}: as_str");
        assert_eq!(z.to_string(), *canonical, "{canonical}: Display");
        assert_eq!(z.as_bytes(), canonical.as_bytes(), "{canonical}: as_bytes");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Validation rejects malformed zones (negative path on construction)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn try_from_rejects_empty_zone() {
    assert!(ZoneId::try_from(String::new()).is_err());
    assert!("".parse::<ZoneId>().is_err());
}

#[test]
fn try_from_rejects_non_z_prefix() {
    // Canonical zone ids start with `z:`.
    assert!(ZoneId::try_from("work".to_string()).is_err());
    assert!(ZoneId::try_from("zone:work".to_string()).is_err());
}

#[test]
fn try_from_rejects_uppercase() {
    assert!(ZoneId::try_from("Z:work".to_string()).is_err());
    assert!(ZoneId::try_from("z:Work".to_string()).is_err());
}
