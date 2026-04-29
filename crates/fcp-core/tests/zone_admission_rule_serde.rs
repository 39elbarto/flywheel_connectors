//! Pin `PolicyPattern` matcher truth table + serde shape — the closest
//! analogue to "ZoneAdmissionRule serde" (flywheel_connectors-bdxjo).
//!
//! Bead asks for `ZoneAdmissionRule` JSON+CBOR roundtrip pinning. No type
//! literally named `ZoneAdmissionRule` exists in fcp-core. The closest
//! singular-rule analogue is [`PolicyPattern`] at
//! `crates/fcp-core/src/policy.rs:216` — a single-field bounded glob rule
//! used in `ZonePolicyObject`'s admission lists (principal_allow,
//! principal_deny, connector_allow, connector_deny, capability_allow,
//! capability_deny). The collective admission-policy struct is already
//! pinned by `zone_admission_policy_serde.rs`; the *singular rule* and
//! its match-truth-table are not yet pinned.
//!
//! Existing `policy_router_route_key_dispatch.rs` covers the basic
//! PolicyPattern JSON shape + CBOR round-trip. This pin adds:
//!   * `.matches()` truth table covering literal, `*`, `?`, prefix,
//!     suffix, middle, double-star, single-char-glob, empty-pattern,
//!     and mismatch cases,
//!   * CBOR Value-inspection on the `Map { "pattern": Text }` shape,
//!   * JSON+CBOR cross-format decode equality,
//!   * Empty + Unicode + special-character pattern strings round-trip,
//!   * Round-trip determinism (same struct → byte-for-byte same JSON),
//!   * Vec<PolicyPattern> serialization (the on-wire shape used in
//!     admission lists) preserves order through round-trip,
//!   * Vec admission-list .matches() OR-semantics via pure pattern
//!     match (no engine) — pinning that admission rules form an
//!     OR-disjunction.

use ciborium::Value as CborValue;
use fcp_core::PolicyPattern;
use serde_json::json;

fn pat(s: &str) -> PolicyPattern {
    PolicyPattern {
        pattern: s.to_string(),
    }
}

#[test]
fn matches_literal_pattern_requires_exact_match() {
    let p = pat("user:alice");
    assert!(p.matches("user:alice"));
    assert!(!p.matches("user:bob"));
    assert!(!p.matches("user:alic"));
    assert!(!p.matches("user:alice2"));
    assert!(!p.matches(""));
}

#[test]
fn matches_star_glob_at_suffix() {
    let p = pat("user:*");
    assert!(p.matches("user:alice"));
    assert!(p.matches("user:"));
    assert!(p.matches("user:alice@example.com"));
    assert!(!p.matches("admin:alice"));
    assert!(!p.matches("us"));
    assert!(!p.matches(""));
}

#[test]
fn matches_star_glob_at_prefix() {
    let p = pat("*:admin");
    assert!(p.matches("user:admin"));
    assert!(p.matches(":admin"));
    assert!(p.matches("service:admin"));
    assert!(!p.matches("user:admins"));
    assert!(!p.matches("admin"));
}

#[test]
fn matches_star_glob_in_middle() {
    let p = pat("user:*:admin");
    assert!(p.matches("user:alice:admin"));
    assert!(p.matches("user::admin"));
    assert!(!p.matches("user:alice:user"));
    assert!(!p.matches("user:alice"));
}

#[test]
fn matches_double_star_glob() {
    let p = pat("**");
    assert!(p.matches(""));
    assert!(p.matches("anything"));
    assert!(p.matches("user:alice"));
    assert!(p.matches("a/b/c/d"));
}

#[test]
fn matches_single_star_matches_empty() {
    let p = pat("*");
    assert!(p.matches(""));
    assert!(p.matches("a"));
    assert!(p.matches("anything-at-all"));
}

#[test]
fn matches_question_mark_is_single_ascii_char() {
    let p = pat("user:?");
    assert!(p.matches("user:a"));
    assert!(p.matches("user:Z"));
    assert!(!p.matches("user:"));
    assert!(!p.matches("user:ab"));
    // No-match: trailing chars after the '?'.
    assert!(!p.matches("user:abc"));
}

#[test]
fn matches_empty_pattern_only_matches_empty_value() {
    let p = pat("");
    assert!(p.matches(""));
    assert!(!p.matches("anything"));
    assert!(!p.matches(" "));
}

#[test]
fn matches_does_not_treat_dot_or_colon_specially() {
    // Pattern matcher is glob, NOT regex — `.` is a literal char.
    let p = pat("user.alice");
    assert!(p.matches("user.alice"));
    assert!(!p.matches("userXalice"));
    assert!(!p.matches("user_alice"));
}

#[test]
fn json_shape_pins_single_pattern_key() {
    let p = pat("user:alice");
    let v = serde_json::to_value(&p).unwrap();
    let obj = v.as_object().expect("must be object");
    assert_eq!(obj.len(), 1, "PolicyPattern shape drift: {obj:?}");
    assert_eq!(obj.get("pattern"), Some(&json!("user:alice")));

    let back: PolicyPattern = serde_json::from_value(v).unwrap();
    assert_eq!(back.pattern, "user:alice");
}

#[test]
fn json_shape_preserves_empty_pattern_string() {
    let p = pat("");
    let v = serde_json::to_value(&p).unwrap();
    assert_eq!(v, json!({ "pattern": "" }));
    let back: PolicyPattern = serde_json::from_value(v).unwrap();
    assert_eq!(back.pattern, "");
}

#[test]
fn json_shape_preserves_unicode_and_special_chars_through_roundtrip() {
    let edge_cases = [
        "user:アリス",
        r#"user:contains-"quote""#,
        r"user:contains\backslash",
        "user:\nwith-newline",
        "user:🎉",
        "*",
        "?",
        "**",
        "user:**:admin",
    ];
    for case in edge_cases {
        let p = pat(case);
        let bytes = serde_json::to_vec(&p).unwrap();
        let back: PolicyPattern = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.pattern, case, "JSON round-trip drift on `{case}`");
    }
}

#[test]
fn cbor_value_inspection_pins_map_with_pattern_text_key() {
    let p = pat("user:*");
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&p, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("expected Map, got {other:?}"),
    };
    assert_eq!(map.len(), 1, "PolicyPattern CBOR shape drift");
    let (key, val) = &map[0];
    match key {
        CborValue::Text(t) => assert_eq!(t, "pattern"),
        other => panic!("expected Text key, got {other:?}"),
    }
    match val {
        CborValue::Text(t) => assert_eq!(t, "user:*"),
        other => panic!("expected Text value, got {other:?}"),
    }
}

#[test]
fn cbor_roundtrip_for_edge_patterns() {
    for case in ["user:*", "", "*", "user:?", "service:**:admin"] {
        let p = pat(case);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&p, &mut bytes).unwrap();
        let back: PolicyPattern = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.pattern, case, "CBOR roundtrip drift on `{case}`");
    }
}

#[test]
fn json_and_cbor_decode_to_same_pattern() {
    let p = pat("connector:github-*");
    let json_bytes = serde_json::to_vec(&p).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&p, &mut cbor_bytes).unwrap();

    let from_json: PolicyPattern = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: PolicyPattern = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    assert_eq!(from_json.pattern, from_cbor.pattern);
    assert_eq!(from_json.pattern, "connector:github-*");
}

#[test]
fn serialization_is_deterministic_byte_for_byte_for_same_struct() {
    // Same input → same bytes. This is critical because admission rules
    // get hashed into PolicyBundle bundle_hash; non-deterministic ordering
    // would invalidate the canonicalization.
    let p1 = pat("user:alice");
    let p2 = pat("user:alice");
    let b1 = serde_json::to_vec(&p1).unwrap();
    let b2 = serde_json::to_vec(&p2).unwrap();
    assert_eq!(b1, b2);
}

#[test]
fn vec_of_admission_rules_preserves_order_through_roundtrip() {
    // Admission lists in ZonePolicyObject are Vec<PolicyPattern>. Pin that
    // order survives JSON + CBOR round-trip: a future serializer that sorts
    // alphabetically would silently reorder operator-curated allow/deny lists.
    let rules = vec![
        pat("user:alice"),
        pat("user:bob"),
        pat("service:*"),
        pat("agent:*"),
    ];
    let json_bytes = serde_json::to_vec(&rules).unwrap();
    let from_json: Vec<PolicyPattern> = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(from_json.len(), rules.len());
    for (i, original) in rules.iter().enumerate() {
        assert_eq!(from_json[i].pattern, original.pattern);
    }

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&rules, &mut cbor_bytes).unwrap();
    let from_cbor: Vec<PolicyPattern> = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    for (i, original) in rules.iter().enumerate() {
        assert_eq!(from_cbor[i].pattern, original.pattern);
    }
}

#[test]
fn admission_list_or_semantics_via_pattern_matches() {
    // Pin the admission-rule semantics: a value is admitted if ANY pattern
    // in the list matches (OR). This matches the `matches_any` helper at
    // policy.rs:2757 used by check_pattern_lists. Re-derive the OR via
    // direct .matches() to avoid coupling to the engine internal API.
    let allow_list = vec![pat("user:alice"), pat("service:*")];

    // Single-rule match.
    assert!(allow_list.iter().any(|p| p.matches("user:alice")));
    // OR-shadow: matches via the second rule's glob.
    assert!(allow_list.iter().any(|p| p.matches("service:foo")));
    // No match across either rule.
    assert!(!allow_list.iter().any(|p| p.matches("user:bob")));
    // Empty list → never matches.
    let empty: Vec<PolicyPattern> = vec![];
    assert!(!empty.iter().any(|p| p.matches("user:alice")));
}

#[test]
fn distinct_patterns_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    let patterns = ["user:alice", "user:bob", "user:*", "*", "*:admin", ""];
    for s in patterns {
        let p = pat(s);
        let v = serde_json::to_value(&p).unwrap();
        assert!(seen.insert(v.clone()), "duplicate JSON for `{s}`: {v:?}");
    }
}
