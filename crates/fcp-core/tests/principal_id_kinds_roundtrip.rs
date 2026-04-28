//! Pin `PrincipalId` equality + `Display` / `FromStr` round-trip
//! stability across user / agent / service principal kinds
//! (flywheel_connectors-qc2pq).
//!
//! `PrincipalId` (capability.rs:790) is the actor identity that
//! every audit event, capability token, decision receipt, and
//! enforcement check carries. The "kind" of a principal is encoded
//! by convention in the canonical-id prefix:
//!
//!   - `user:<name>` — human / operator principal
//!   - `agent:<name>` — autonomous agent principal
//!   - `service:<name>` — service-account / connector principal
//!
//! The kind prefix is NOT enforced at the type level (canonical
//! validation rules only require ASCII-lower / dot / `-` / `_` /
//! `:`), so the test pins:
//!
//!   1. Display ↔ FromStr round-trip is byte-stable across all
//!      three documented kinds (and a few real-world variants).
//!   2. Equality + Hash hold across construction paths
//!      (`new` / `try_from` / `parse` / `clone`).
//!   3. Distinct kinds with the same suffix produce distinct
//!      principals (i.e. the `:` in `user:alice` vs `agent:alice`
//!      is preserved through the round-trip and contributes to
//!      identity).
//!   4. AsRef<str> agrees with `as_str()` and `Display`.
//!   5. The empty principal and invalid kinds are rejected.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use fcp_core::PrincipalId;

const PRINCIPALS: &[&str] = &[
    // user kind
    "user:alice",
    "user:bob",
    "user:operator-1",
    "user:ops.team.alpha",
    // agent kind
    "agent:planner",
    "agent:planner-v2",
    "agent:assistant.r1",
    // service kind
    "service:gateway",
    "service:credential-vault",
    "service:fcp.host.alpha",
    // multi-segment principals (the canonical-id rules permit `:`)
    "user:org.example.alice",
    "agent:org.example.planner.v3",
    "service:fcp.connector.gmail",
];

fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Display ↔ FromStr round-trip across all three kinds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn display_fromstr_roundtrip_pinned_for_each_kind() {
    for canonical in PRINCIPALS {
        let p = PrincipalId::new(*canonical)
            .unwrap_or_else(|err| panic!("PrincipalId::new({canonical}): {err}"));

        // Display MUST emit the canonical input verbatim.
        let displayed = p.to_string();
        assert_eq!(
            displayed, *canonical,
            "Display MUST emit the canonical input verbatim for {canonical}"
        );

        // FromStr on the Display output MUST round-trip to the same
        // PrincipalId (Eq + Hash).
        let parsed = PrincipalId::from_str(&displayed)
            .unwrap_or_else(|err| panic!("FromStr roundtrip {canonical}: {err}"));
        assert_eq!(
            p, parsed,
            "Display → FromStr round-trip lost equality for {canonical}"
        );
        assert_eq!(
            hash_of(&p),
            hash_of(&parsed),
            "Display → FromStr round-trip lost hash for {canonical}"
        );
    }
}

#[test]
fn display_is_idempotent_under_repeat_format() {
    // Calling Display twice on the same principal MUST return the
    // same string. Pins format-stability under repeated formatting.
    for canonical in PRINCIPALS {
        let p = PrincipalId::new(*canonical).expect("canonical");
        let a = p.to_string();
        let b = format!("{p}");
        let c = format!("{p}");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Equality + Hash across construction paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn equality_and_hash_across_construction_paths() {
    for canonical in PRINCIPALS {
        let via_new = PrincipalId::new(*canonical).expect("new");
        let via_try_from = PrincipalId::try_from((*canonical).to_string()).expect("try_from");
        let via_parse = canonical.parse::<PrincipalId>().expect("FromStr");
        let via_clone = via_new.clone();
        let via_display_rt = PrincipalId::from_str(&via_new.to_string()).expect("Display rt");

        // Equality.
        assert_eq!(via_new, via_try_from, "{canonical}: new vs try_from");
        assert_eq!(via_new, via_parse, "{canonical}: new vs parse");
        assert_eq!(via_new, via_clone, "{canonical}: new vs clone");
        assert_eq!(via_new, via_display_rt, "{canonical}: new vs Display rt");

        // Hash.
        let h = hash_of(&via_new);
        assert_eq!(h, hash_of(&via_try_from), "{canonical}: hash try_from");
        assert_eq!(h, hash_of(&via_parse), "{canonical}: hash parse");
        assert_eq!(h, hash_of(&via_clone), "{canonical}: hash clone");
        assert_eq!(h, hash_of(&via_display_rt), "{canonical}: hash Display rt");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Cross-kind distinctness — the kind prefix is part of identity
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn different_kinds_with_same_suffix_are_distinct_principals() {
    // user:alice, agent:alice, service:alice are three different
    // principals even though they share the suffix.
    let user = PrincipalId::new("user:alice").expect("user kind");
    let agent = PrincipalId::new("agent:alice").expect("agent kind");
    let service = PrincipalId::new("service:alice").expect("service kind");

    assert_ne!(user, agent);
    assert_ne!(user, service);
    assert_ne!(agent, service);

    // Distinctness extends to the hash class — sanity-check on the
    // hasher (Hash contract permits collisions but for these inputs
    // we expect distinct u64s).
    let hashes = [hash_of(&user), hash_of(&agent), hash_of(&service)];
    let unique: std::collections::HashSet<u64> = hashes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        hashes.len(),
        "kind prefixes MUST contribute to the hash; got collisions {hashes:?}"
    );
}

#[test]
fn same_kind_different_suffix_are_distinct_principals() {
    let alice = PrincipalId::new("user:alice").expect("user alice");
    let bob = PrincipalId::new("user:bob").expect("user bob");
    assert_ne!(alice, bob);
    assert_ne!(hash_of(&alice), hash_of(&bob));
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. AsRef + as_str + Display agree
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn as_ref_as_str_display_agree() {
    for canonical in PRINCIPALS {
        let p = PrincipalId::new(*canonical).expect("canonical");
        let via_as_ref: &str = p.as_ref();
        assert_eq!(via_as_ref, *canonical, "AsRef<str> view for {canonical}");
        assert_eq!(p.as_str(), *canonical, "as_str view for {canonical}");
        assert_eq!(p.to_string(), *canonical, "Display for {canonical}");
        assert_eq!(via_as_ref, p.as_str());
        assert_eq!(p.as_str(), p.to_string());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. HashMap-key correctness across kinds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn principal_id_serves_as_hashmap_key_across_kinds() {
    use std::collections::HashMap;
    let mut map: HashMap<PrincipalId, &'static str> = HashMap::new();
    map.insert(PrincipalId::new("user:alice").unwrap(), "u-alice");
    map.insert(PrincipalId::new("agent:alice").unwrap(), "a-alice");
    map.insert(PrincipalId::new("service:alice").unwrap(), "s-alice");
    assert_eq!(map.len(), 3, "three distinct kinds MUST produce 3 keys");

    // Look up via fresh Display→FromStr round-trips.
    let lookup_user = "user:alice".parse::<PrincipalId>().unwrap();
    let lookup_agent = "agent:alice".parse::<PrincipalId>().unwrap();
    let lookup_service = "service:alice".parse::<PrincipalId>().unwrap();
    assert_eq!(map.get(&lookup_user), Some(&"u-alice"));
    assert_eq!(map.get(&lookup_agent), Some(&"a-alice"));
    assert_eq!(map.get(&lookup_service), Some(&"s-alice"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Validation: rejected forms
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_principal_is_rejected() {
    assert!(
        PrincipalId::new("").is_err(),
        "empty PrincipalId MUST be rejected"
    );
    assert!(
        PrincipalId::from_str("").is_err(),
        "FromStr on empty MUST be rejected"
    );
}

#[test]
fn principal_with_uppercase_or_unicode_is_rejected() {
    // Canonical-id rules: ASCII-lower only.
    assert!(
        PrincipalId::new("User:Alice").is_err(),
        "uppercase MUST be rejected"
    );
    assert!(
        PrincipalId::new("user:café").is_err(),
        "non-ASCII MUST be rejected"
    );
}

#[test]
fn principal_with_whitespace_or_control_is_rejected() {
    assert!(
        PrincipalId::new("user:al ice").is_err(),
        "whitespace MUST be rejected"
    );
    assert!(
        PrincipalId::new("user:al\nice").is_err(),
        "newline MUST be rejected"
    );
    assert!(
        PrincipalId::new("user:al\0ice").is_err(),
        "NUL MUST be rejected"
    );
}

#[test]
fn principal_starting_with_separator_is_rejected() {
    // Canonical-id rules require first char to be alphanumeric.
    assert!(
        PrincipalId::new(":user:alice").is_err(),
        "leading `:` MUST be rejected"
    );
    assert!(
        PrincipalId::new(".user:alice").is_err(),
        "leading `.` MUST be rejected"
    );
    assert!(
        PrincipalId::new("-user").is_err(),
        "leading `-` MUST be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Serde round-trip mirrors the Display/FromStr round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_roundtrip_pinned_for_each_kind() {
    for canonical in PRINCIPALS {
        let p = PrincipalId::new(*canonical).expect("canonical");
        let json = serde_json::to_string(&p).expect("serialize");
        // serde uses `into = "String"` so JSON form is just the
        // quoted canonical string.
        assert_eq!(
            json,
            format!("\"{canonical}\""),
            "JSON form MUST be the quoted canonical id for {canonical}"
        );
        let back: PrincipalId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back, "JSON round-trip lost equality for {canonical}");
        assert_eq!(hash_of(&p), hash_of(&back));
    }
}
