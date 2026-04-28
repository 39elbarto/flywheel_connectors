//! Pin the Hash-then-Equality contract on canonical fcp-core
//! identifiers (flywheel_connectors-llp14).
//!
//! Rust's `Hash` documentation requires:
//!
//! > It is important that the following property holds:
//! > `k1 == k2 → hash(k1) == hash(k2)`
//!
//! Violating this invariant breaks `HashMap`, `HashSet`, and every
//! other hash-keyed data structure these identifiers flow through.
//! Audit-event chains, capability lookups, zone routing, and node
//! coordination all rely on hash-stable equality.
//!
//! For each canonical id type with `Hash + Eq`, this test constructs
//! two values that ARE equal via different paths (clone, FromStr ↔
//! Display round-trip, struct-literal vs constructor, alternate
//! Into<String> sources, parse-prefixed forms, etc.) and asserts
//! `hash(a) == hash(b)` whenever `a == b`.
//!
//! Hashing uses `std::collections::hash_map::DefaultHasher` because
//! that is the same hasher backing `HashMap`'s default state — the
//! only hasher whose collisions matter at runtime. Drift in any of
//! the underlying types (e.g. switching `String` ↔ `Arc<str>`,
//! `[u8; 32]` ↔ `Vec<u8>`, or adding a new private field that derives
//! Hash but not Eq) shows up here.
//!
//! Types covered:
//! - `ZoneId` (Arc<str>)
//! - `CapabilityId` (Arc<str>)
//! - `InstanceId` (Arc<str>)
//! - `ObjectId` ([u8; 32])
//! - `NodeId` (String) — the quorum-multisig identifier in fcp-core

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use fcp_core::{CapabilityId, InstanceId, NodeId, ObjectId, ZoneId};

/// Hash one value through a fresh `DefaultHasher` and return the u64
/// fingerprint. Using a fresh hasher per call mirrors how `HashMap`
/// invokes the trait — different per-process seeds can shift the
/// absolute output but two values from the SAME process MUST agree.
fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Generic property: assert that `a == b` AND `hash(a) == hash(b)`.
fn assert_hash_eq_contract<T: Hash + Eq + std::fmt::Debug>(label: &str, a: T, b: T) {
    assert_eq!(
        a, b,
        "{label}: Eq violated — values constructed via different paths are not equal: \
         {a:?} vs {b:?}"
    );
    let ha = hash_of(&a);
    let hb = hash_of(&b);
    assert_eq!(
        ha, hb,
        "{label}: HASH-EQ CONTRACT VIOLATION — a == b but hash(a)={ha} != hash(b)={hb}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneId
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_id_canonical_hash_eq_contract() {
    // The five canonical zones — verify each constructor path reaches
    // the same hash class.
    let cases = [
        ("z:owner", ZoneId::owner()),
        ("z:private", ZoneId::private()),
        ("z:work", ZoneId::work()),
        ("z:community", ZoneId::community()),
        ("z:public", ZoneId::public()),
    ];
    for (canonical, via_factory) in cases {
        let via_try_from = ZoneId::try_from(canonical.to_string())
            .unwrap_or_else(|err| panic!("ZoneId::try_from({canonical}) must succeed: {err}"));
        let via_parse = canonical
            .parse::<ZoneId>()
            .unwrap_or_else(|err| panic!("ZoneId::parse({canonical}) must succeed: {err}"));
        let via_clone = via_factory.clone();
        let via_display_roundtrip = ZoneId::try_from(via_factory.to_string())
            .expect("Display → try_from round-trip must succeed");

        assert_hash_eq_contract(
            &format!("ZoneId({canonical}) factory vs try_from"),
            via_factory.clone(),
            via_try_from,
        );
        assert_hash_eq_contract(
            &format!("ZoneId({canonical}) factory vs parse"),
            via_factory.clone(),
            via_parse,
        );
        assert_hash_eq_contract(
            &format!("ZoneId({canonical}) factory vs clone"),
            via_factory.clone(),
            via_clone,
        );
        assert_hash_eq_contract(
            &format!("ZoneId({canonical}) factory vs Display roundtrip"),
            via_factory,
            via_display_roundtrip,
        );
    }
}

#[test]
fn zone_id_project_subzone_hash_eq_contract() {
    // Sub-namespace `z:project:<name>` — exercises the variable-length
    // suffix path under Arc<str> backing.
    let canonical = "z:project:alpha-team";
    let a = ZoneId::try_from(canonical.to_string()).expect("project zone");
    let b = ZoneId::from_str(canonical).expect("project zone via FromStr");
    let c = a.clone();
    assert_hash_eq_contract(
        "ZoneId(z:project:alpha-team) try_from vs FromStr",
        a.clone(),
        b,
    );
    assert_hash_eq_contract("ZoneId(z:project:alpha-team) clone", a, c);
}

#[test]
fn zone_id_unequal_values_may_diverge_in_hash() {
    // The Hash contract does NOT require `a != b ⇒ hash(a) != hash(b)`
    // (collisions are allowed). But on these canonical zones we expect
    // them to in fact differ — pin that as a sanity-check on the
    // hasher producing useful output instead of always returning 0.
    let owner = hash_of(&ZoneId::owner());
    let private = hash_of(&ZoneId::private());
    let work = hash_of(&ZoneId::work());
    let community = hash_of(&ZoneId::community());
    let public = hash_of(&ZoneId::public());
    let all = [owner, private, work, community, public];
    let unique: std::collections::HashSet<u64> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all.len(),
        "expected canonical zones to hash to distinct u64 values; got {all:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CapabilityId
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_id_hash_eq_contract() {
    let canonical_inputs = ["read", "write", "fcp.connector.invoke", "x.y.z-1.2"];
    for canonical in canonical_inputs {
        let via_new = CapabilityId::new(canonical)
            .unwrap_or_else(|err| panic!("CapabilityId::new({canonical}) must succeed: {err}"));
        let via_static = CapabilityId::from_static(canonical);
        let via_try_from = CapabilityId::try_from(canonical.to_string())
            .expect("try_from must succeed on canonical input");
        let via_parse = canonical
            .parse::<CapabilityId>()
            .expect("FromStr parse must succeed on canonical input");
        let via_clone = via_new.clone();
        let via_display_roundtrip = CapabilityId::try_from(via_new.to_string())
            .expect("Display → try_from round-trip must succeed");

        assert_hash_eq_contract(
            &format!("CapabilityId({canonical}) new vs from_static"),
            via_new.clone(),
            via_static,
        );
        assert_hash_eq_contract(
            &format!("CapabilityId({canonical}) new vs try_from"),
            via_new.clone(),
            via_try_from,
        );
        assert_hash_eq_contract(
            &format!("CapabilityId({canonical}) new vs parse"),
            via_new.clone(),
            via_parse,
        );
        assert_hash_eq_contract(
            &format!("CapabilityId({canonical}) new vs clone"),
            via_new.clone(),
            via_clone,
        );
        assert_hash_eq_contract(
            &format!("CapabilityId({canonical}) new vs Display roundtrip"),
            via_new,
            via_display_roundtrip,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstanceId
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn instance_id_hash_eq_contract() {
    let canonical_inputs = ["inst-1", "inst.2.3", "fcp.host.alpha"];
    for canonical in canonical_inputs {
        let via_new = InstanceId::try_from(canonical.to_string())
            .unwrap_or_else(|err| panic!("InstanceId::try_from({canonical}): {err}"));
        let via_try_from =
            InstanceId::try_from(canonical.to_string()).expect("InstanceId try_from must succeed");
        let via_parse = canonical
            .parse::<InstanceId>()
            .expect("InstanceId FromStr must succeed");
        let via_clone = via_new.clone();
        let via_display_roundtrip =
            InstanceId::try_from(via_new.to_string()).expect("Display → try_from round-trip");

        assert_hash_eq_contract(
            &format!("InstanceId({canonical}) new vs try_from"),
            via_new.clone(),
            via_try_from,
        );
        assert_hash_eq_contract(
            &format!("InstanceId({canonical}) new vs parse"),
            via_new.clone(),
            via_parse,
        );
        assert_hash_eq_contract(
            &format!("InstanceId({canonical}) new vs clone"),
            via_new.clone(),
            via_clone,
        );
        assert_hash_eq_contract(
            &format!("InstanceId({canonical}) new vs Display roundtrip"),
            via_new,
            via_display_roundtrip,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjectId
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn object_id_hash_eq_contract() {
    // Hand-picked byte patterns — boundary, all-zero, all-one, mixed.
    let cases: [[u8; 32]; 4] = [
        [0x00; 32],
        [0xFF; 32],
        {
            let mut b = [0u8; 32];
            for (i, slot) in b.iter_mut().enumerate() {
                *slot = i as u8;
            }
            b
        },
        [0x42; 32],
    ];

    for bytes in cases {
        let via_from_bytes = ObjectId::from_bytes(bytes);
        let via_clone = via_from_bytes;
        let via_parse = ObjectId::parse_prefixed(&hex::encode(bytes))
            .expect("ObjectId::parse_prefixed (bare hex) must succeed");
        let via_parse_prefixed = ObjectId::parse_prefixed(&via_from_bytes.to_prefixed_string())
            .expect("ObjectId::parse_prefixed (objectid:hex) must succeed");
        let via_display_roundtrip = ObjectId::parse_prefixed(&via_from_bytes.to_string())
            .expect("Display → parse_prefixed round-trip");

        let label = format!("ObjectId({})", hex::encode(bytes));
        assert_hash_eq_contract(
            &format!("{label} from_bytes vs Copy"),
            via_from_bytes,
            via_clone,
        );
        assert_hash_eq_contract(
            &format!("{label} from_bytes vs parse_prefixed(bare hex)"),
            via_from_bytes,
            via_parse,
        );
        assert_hash_eq_contract(
            &format!("{label} from_bytes vs parse_prefixed(objectid:hex)"),
            via_from_bytes,
            via_parse_prefixed,
        );
        assert_hash_eq_contract(
            &format!("{label} from_bytes vs Display roundtrip"),
            via_from_bytes,
            via_display_roundtrip,
        );
    }
}

#[test]
fn object_id_uppercase_hex_normalizes_to_same_value() {
    // ObjectId::parse_prefixed accepts mixed-case hex but the inner
    // representation is the byte array — so the upper/lower forms
    // MUST produce equal ObjectIds and equal hashes.
    let lower_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let upper_hex = lower_hex.to_uppercase();
    let lower = ObjectId::parse_prefixed(lower_hex).expect("lowercase parse");
    let upper = ObjectId::parse_prefixed(&upper_hex).expect("uppercase parse");
    assert_hash_eq_contract("ObjectId(deadbeef...) lowercase vs uppercase", lower, upper);
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeId (fcp_core::quorum::NodeId — used for multi-sig canonicalization)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn node_id_hash_eq_contract() {
    // NodeId wraps a String. Equal strings (constructed via different
    // Into<String> paths) MUST hash identically.
    let canonical_inputs = ["alice", "bob.example.com", "node-1234"];
    for canonical in canonical_inputs {
        let via_new_owned = NodeId::new(String::from(canonical));
        let via_new_borrowed = NodeId::new(canonical);
        let via_clone = via_new_owned.clone();

        assert_hash_eq_contract(
            &format!("NodeId({canonical}) String vs &str"),
            via_new_owned.clone(),
            via_new_borrowed,
        );
        assert_hash_eq_contract(
            &format!("NodeId({canonical}) clone"),
            via_new_owned,
            via_clone,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-type sanity: the contract holds when these types are nested
// inside collection containers (HashMap key, HashSet element).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_types_serve_as_hashmap_keys_correctly() {
    use std::collections::HashMap;

    // Construct a HashMap keyed on each id type, insert via one path,
    // and look up via another — round-trip MUST succeed.
    let mut zone_map: HashMap<ZoneId, &'static str> = HashMap::new();
    zone_map.insert(ZoneId::work(), "work-data");
    let lookup = ZoneId::try_from("z:work".to_string()).unwrap();
    assert_eq!(
        zone_map.get(&lookup),
        Some(&"work-data"),
        "ZoneId HashMap lookup via try_from MUST find the entry inserted via factory"
    );

    let mut cap_map: HashMap<CapabilityId, u64> = HashMap::new();
    cap_map.insert(CapabilityId::from_static("read"), 1);
    let cap_lookup = "read".parse::<CapabilityId>().unwrap();
    assert_eq!(cap_map.get(&cap_lookup), Some(&1));

    let mut inst_map: HashMap<InstanceId, u64> = HashMap::new();
    inst_map.insert(InstanceId::try_from("inst-1".to_string()).unwrap(), 7);
    let inst_lookup = InstanceId::try_from("inst-1".to_string()).unwrap();
    assert_eq!(inst_map.get(&inst_lookup), Some(&7));

    let mut obj_map: HashMap<ObjectId, u64> = HashMap::new();
    let bytes = [0x33u8; 32];
    obj_map.insert(ObjectId::from_bytes(bytes), 42);
    let obj_lookup = ObjectId::parse_prefixed(&hex::encode(bytes)).unwrap();
    assert_eq!(obj_map.get(&obj_lookup), Some(&42));

    let mut node_map: HashMap<NodeId, u64> = HashMap::new();
    node_map.insert(NodeId::new("alice"), 100);
    let node_lookup = NodeId::new("alice".to_string());
    assert_eq!(node_map.get(&node_lookup), Some(&100));
}
