//! Pin string-backed identifier equality and hash semantics across
//! content size classes (flywheel_connectors-v112c).
//!
//! The bead asks for "CompactString-backed identifier equality+hash"
//! coverage; no `CompactString` (the `compact_str` crate) is in use
//! in fcp-core or anywhere else in the workspace at the time of
//! writing — the canonical fcp-core IDs are `Arc<str>` backed
//! (CapabilityId, InstanceId, ZoneId, PrincipalId) or `String`
//! backed (`quorum::NodeId`). Either backing has the same
//! observable contract: equal values MUST hash identically and
//! MUST be equal under `==`, regardless of which construction path
//! produced them OR what content-size class the value belongs to.
//!
//! The companion test `hash_eq_contract.rs` (bead llp14) covered the
//! construction-path axis (clone / FromStr / TryFrom<String> /
//! from_static / Display roundtrip / String vs &str). This test
//! adds the orthogonal axis: content size class. Specifically it
//! pins the contract holds on:
//!
//! - **Short** content (1-byte): the smallest legal canonical id.
//! - **Boundary-23** content: 23 bytes is the largest size that fits
//!   inline in `compact_str::CompactString` if the project ever
//!   migrates. Pinning it now makes a future migration drop into
//!   place without surprises.
//! - **Boundary-24** content: the first heap-allocating size for
//!   `CompactString`. The "inline vs heap" distinction MUST be
//!   invisible to Eq+Hash.
//! - **Long** content (100+ bytes, capped at the canonical-id
//!   length limit of 128).
//!
//! Each size class is constructed via three different paths and
//! then asserted equal + same-hash via a `DefaultHasher`.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use fcp_core::{CapabilityId, InstanceId, NodeId, PrincipalId, ZoneId};

/// Hash via `DefaultHasher` — the same hasher backing `HashMap`'s
/// default state.
fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Generic property: assert `a == b` AND `hash(a) == hash(b)`.
fn assert_hash_eq<T: Hash + Eq + std::fmt::Debug>(label: &str, a: T, b: T) {
    assert_eq!(a, b, "{label}: equality violated: {a:?} vs {b:?}");
    let ha = hash_of(&a);
    let hb = hash_of(&b);
    assert_eq!(
        ha, hb,
        "{label}: HASH-EQ CONTRACT — a == b but hash(a)={ha} != hash(b)={hb}"
    );
}

/// Build a canonical id payload of `len` bytes filled with the
/// pattern `<prefix>` + repeated `<filler>` to reach exactly `len`
/// total bytes. The result is a valid canonical id (lowercase
/// alphanumeric / `.` / `-` / `_` / `:`) per FCP §3.1.
fn canonical_payload(len: usize, prefix: &str) -> String {
    assert!(prefix.len() <= len);
    let mut s = String::with_capacity(len);
    s.push_str(prefix);
    while s.len() < len {
        s.push('a');
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// CapabilityId — Arc<str> backed, 1-byte to long content
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_id_short_size_class_hash_eq() {
    // 1-byte canonical id — smallest legal value.
    let payload = "a";
    assert_hash_eq_capability_id(payload);
}

#[test]
fn capability_id_boundary_23_byte_size_class_hash_eq() {
    // 23 bytes — last inline size for compact_str if migrated.
    let payload = canonical_payload(23, "cap.");
    assert_eq!(payload.len(), 23);
    assert_hash_eq_capability_id(&payload);
}

#[test]
fn capability_id_boundary_24_byte_size_class_hash_eq() {
    // 24 bytes — first heap size for compact_str if migrated.
    let payload = canonical_payload(24, "cap.");
    assert_eq!(payload.len(), 24);
    assert_hash_eq_capability_id(&payload);
}

#[test]
fn capability_id_long_size_class_hash_eq() {
    // 100-byte canonical id — well past any inline boundary.
    let payload = canonical_payload(100, "cap.long.");
    assert_eq!(payload.len(), 100);
    assert_hash_eq_capability_id(&payload);
}

#[test]
fn capability_id_max_length_size_class_hash_eq() {
    // 128 bytes — the documented canonical-id length cap.
    let payload = canonical_payload(128, "cap.cap.cap.cap.");
    assert_eq!(payload.len(), 128);
    assert_hash_eq_capability_id(&payload);
}

fn assert_hash_eq_capability_id(payload: &str) {
    let label = format!("CapabilityId({} bytes)", payload.len());
    let via_new = CapabilityId::new(payload).expect("canonical id must validate");
    let via_try_from = CapabilityId::try_from(payload.to_string()).expect("try_from canonical id");
    let via_parse = payload
        .parse::<CapabilityId>()
        .expect("FromStr canonical id");
    let via_clone = via_new.clone();
    let via_display = CapabilityId::try_from(via_new.to_string()).expect("Display roundtrip");

    assert_hash_eq(
        &format!("{label} new vs try_from"),
        via_new.clone(),
        via_try_from,
    );
    assert_hash_eq(&format!("{label} new vs parse"), via_new.clone(), via_parse);
    assert_hash_eq(&format!("{label} clone"), via_new.clone(), via_clone);
    assert_hash_eq(&format!("{label} Display roundtrip"), via_new, via_display);
}

// ─────────────────────────────────────────────────────────────────────────────
// InstanceId — Arc<str> backed, content-size class sweep
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn instance_id_size_class_sweep_hash_eq() {
    let sizes = [1usize, 5, 23, 24, 50, 100, 128];
    for size in sizes {
        let prefix = if size < "inst.".len() { "i" } else { "inst." };
        let payload = canonical_payload(size, prefix);
        assert_eq!(payload.len(), size);

        let via_try_from = InstanceId::try_from(payload.clone())
            .unwrap_or_else(|err| panic!("{size}-byte InstanceId: {err}"));
        let via_parse = payload
            .parse::<InstanceId>()
            .unwrap_or_else(|err| panic!("{size}-byte InstanceId FromStr: {err}"));
        let via_clone = via_try_from.clone();
        let via_display =
            InstanceId::try_from(via_try_from.to_string()).expect("Display roundtrip");

        assert_hash_eq(
            &format!("InstanceId({size} bytes) try_from vs parse"),
            via_try_from.clone(),
            via_parse,
        );
        assert_hash_eq(
            &format!("InstanceId({size} bytes) clone"),
            via_try_from.clone(),
            via_clone,
        );
        assert_hash_eq(
            &format!("InstanceId({size} bytes) Display roundtrip"),
            via_try_from,
            via_display,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrincipalId — Arc<str> backed, content-size class sweep
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn principal_id_size_class_sweep_hash_eq() {
    let sizes = [1usize, 5, 23, 24, 50, 100, 128];
    for size in sizes {
        let prefix = if size < "p.".len() { "p" } else { "p." };
        let payload = canonical_payload(size, prefix);

        let via_new = PrincipalId::new(&payload).expect("canonical principal id");
        let via_try_from = PrincipalId::try_from(payload.clone()).expect("try_from");
        let via_parse = payload.parse::<PrincipalId>().expect("FromStr");
        let via_clone = via_new.clone();

        assert_hash_eq(
            &format!("PrincipalId({size} bytes) new vs try_from"),
            via_new.clone(),
            via_try_from,
        );
        assert_hash_eq(
            &format!("PrincipalId({size} bytes) new vs parse"),
            via_new.clone(),
            via_parse,
        );
        assert_hash_eq(
            &format!("PrincipalId({size} bytes) clone"),
            via_new,
            via_clone,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneId — Arc<str> backed; canonical zones live at the short end,
//          z:project:<long-name> exercises the long end.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_id_short_size_class_hash_eq() {
    // The five built-in zones: 7-12 byte canonical ids — all short.
    let cases = [
        ("z:owner", ZoneId::owner()),
        ("z:private", ZoneId::private()),
        ("z:work", ZoneId::work()),
        ("z:community", ZoneId::community()),
        ("z:public", ZoneId::public()),
    ];
    for (canonical, factory) in cases {
        let try_from = ZoneId::try_from(canonical.to_string()).expect("zone");
        let parse = canonical.parse::<ZoneId>().expect("zone FromStr");
        let clone = factory.clone();
        let display_rt = ZoneId::try_from(factory.to_string()).expect("Display roundtrip");

        let label = format!("ZoneId({canonical}, {} bytes)", canonical.len());
        assert_hash_eq(
            &format!("{label} factory vs try_from"),
            factory.clone(),
            try_from,
        );
        assert_hash_eq(&format!("{label} factory vs parse"), factory.clone(), parse);
        assert_hash_eq(&format!("{label} clone"), factory.clone(), clone);
        assert_hash_eq(&format!("{label} Display roundtrip"), factory, display_rt);
    }
}

#[test]
fn zone_id_long_project_subzone_hash_eq() {
    // Build a canonical project zone with a long suffix (>23 bytes
    // total) — exercises the long-content path.
    let suffix = canonical_payload(50, "team-");
    let canonical = format!("z:project:{suffix}");
    assert!(canonical.len() > 23);

    let try_from = ZoneId::try_from(canonical.clone()).expect("project zone try_from");
    let parse = ZoneId::from_str(&canonical).expect("project zone FromStr");
    let clone = try_from.clone();
    let display_rt = ZoneId::try_from(try_from.to_string()).expect("Display roundtrip");

    let label = format!("ZoneId(z:project:..., {} bytes)", canonical.len());
    assert_hash_eq(
        &format!("{label} try_from vs parse"),
        try_from.clone(),
        parse,
    );
    assert_hash_eq(&format!("{label} clone"), try_from.clone(), clone);
    assert_hash_eq(&format!("{label} Display roundtrip"), try_from, display_rt);
}

// ─────────────────────────────────────────────────────────────────────────────
// quorum::NodeId — String backed, no validator, full freedom
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quorum_node_id_size_class_sweep_hash_eq() {
    // NodeId is a non-validating String wrapper, so we can use the
    // full inline/heap boundary plus arbitrary lengths without
    // worrying about canonical-id rules.
    let sizes = [0usize, 1, 23, 24, 100, 1_000];
    for size in sizes {
        // NodeId allows any String content; use ASCII letters so the
        // result is identical regardless of construction path.
        let payload: String = std::iter::repeat_n('n', size).collect();

        let via_owned = NodeId::new(payload.clone());
        let via_borrowed = NodeId::new(payload.as_str());
        let via_clone = via_owned.clone();

        assert_hash_eq(
            &format!("NodeId({size} bytes) String vs &str"),
            via_owned.clone(),
            via_borrowed,
        );
        assert_hash_eq(&format!("NodeId({size} bytes) clone"), via_owned, via_clone);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-size HashMap-key correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_ids_short_and_long_serve_as_distinct_hashmap_keys() {
    use std::collections::HashMap;

    let short = CapabilityId::new("a").expect("1-byte cap");
    let long = CapabilityId::new(&canonical_payload(100, "cap.")).expect("100-byte cap");

    let mut map: HashMap<CapabilityId, &'static str> = HashMap::new();
    map.insert(short.clone(), "short-value");
    map.insert(long.clone(), "long-value");
    assert_eq!(map.len(), 2, "short and long IDs must be distinct keys");

    // Look up via a freshly-constructed copy of each — the
    // hash-then-equality contract MUST find them.
    let short_lookup = "a".parse::<CapabilityId>().expect("re-parse short");
    let long_lookup =
        CapabilityId::try_from(canonical_payload(100, "cap.")).expect("re-build long");
    assert_eq!(map.get(&short_lookup), Some(&"short-value"));
    assert_eq!(map.get(&long_lookup), Some(&"long-value"));
}
