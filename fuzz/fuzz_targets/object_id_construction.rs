#![no_main]

//! Fuzz target for `fcp_core::ObjectId::new` keyed-hash domain separation.
//!
//! `ObjectId::new` (object.rs:61-68) is the keyed-hash construction:
//!
//!     BLAKE3-keyed(key, b"FCP2-OBJECT-V2" || zone || schema.hash() || content)
//!
//! Every security-object identity in the mesh derives from this. A regression
//! that dropped one of the four mix steps (the `b"FCP2-OBJECT-V2"` domain tag,
//! the zone, the schema hash, or the keyed-hash bind) would silently collapse
//! one of the bindings without breaking any existing test.
//!
//! Existing fuzz coverage focuses on consumers (`object_id_verifier`,
//! `iblt_decode`, `mesh_post_verify_*`) — none exercise the constructor's
//! domain-separation guarantees.
//!
//! Properties asserted:
//!
//!   1. **Total / panic-free**: `ObjectId::new` accepts any input.
//!   2. **Determinism**: same `(content, zone, schema, key)` ⇒ same id.
//!   3. **Content-binding**: bit-flip in content MUST change the id.
//!   4. **Zone-binding**: same content under different zones MUST yield
//!      distinct ids (closes cross-zone identity-forge surface).
//!   5. **Schema-binding**: same content under different `SchemaId`s MUST
//!      yield distinct ids.
//!   6. **Key-binding**: different `ObjectIdKey` on identical inputs MUST
//!      yield distinct ids — enforces the per-zone privacy guarantee
//!      against dictionary attacks documented at object.rs:118-120.
//!   7. **Domain separation from `from_unscoped_bytes`**:
//!      `ObjectId::new(c,z,s,k)` MUST NOT collide with
//!      `from_unscoped_bytes(c)` for any inputs (the unscoped form is
//!      documented NON-NORMATIVE; cross-collision would let an attacker
//!      promote an unscoped hash into a security-object identity).
//!   8. **`parse_prefixed` round-trip**: every constructed id round-trips
//!      through `to_prefixed_string` → `parse_prefixed`.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_core::{ObjectId, ObjectIdKey, ZoneId};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

const KEY_SIZE: usize = 32;

static DOMAIN_SEPARATION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    content: Vec<u8>,
    key_bytes: [u8; KEY_SIZE],
    /// Selector picks one of the canonical zones; we use the const-construction
    /// helpers rather than parsing arbitrary strings (parser is covered by
    /// `fuzz_zone_id_parse`).
    zone_a_selector: u8,
    zone_b_selector: u8,
    /// Bit index for the content-binding flip.
    bitflip_index: u32,
    /// Schema discriminators kept short to maximise fuzzer coverage of the
    /// hash-input length boundary rather than the schema-string content.
    schema_a_name: u8,
    schema_b_name: u8,
}

fn pick_zone(selector: u8) -> ZoneId {
    match selector % 5 {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn pick_schema(name_disc: u8) -> SchemaId {
    SchemaId::new(
        "fcp.fuzz",
        format!("Type{name_disc}"),
        Version::new(1, 0, 0),
    )
}

fn flip_bit(bytes: &mut [u8], bit_index: usize) {
    let byte = bit_index / 8;
    let mask = 1u8 << (bit_index % 8);
    bytes[byte] ^= mask;
}

fuzz_target!(|data: &[u8]| {
    DOMAIN_SEPARATION_ANCHOR.call_once(assert_domain_separation_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let zone_a = pick_zone(input.zone_a_selector);
    let zone_b = pick_zone(input.zone_b_selector);
    let schema_a = pick_schema(input.schema_a_name);
    let schema_b = pick_schema(input.schema_b_name);
    let key = ObjectIdKey::from_bytes(input.key_bytes);

    // ── PROPERTY 1: total / panic-free ──────────────────────────────────
    let id = ObjectId::new(&input.content, &zone_a, &schema_a, &key);

    // ── PROPERTY 2: determinism ────────────────────────────────────────
    let id_again = ObjectId::new(&input.content, &zone_a, &schema_a, &key);
    assert_eq!(
        id, id_again,
        "ObjectId::new is not deterministic on identical inputs"
    );

    // ── PROPERTY 3: content-binding ────────────────────────────────────
    if !input.content.is_empty() {
        let bit = (input.bitflip_index as usize) % (input.content.len() * 8);
        let mut alt_content = input.content.clone();
        flip_bit(&mut alt_content, bit);
        let alt_id = ObjectId::new(&alt_content, &zone_a, &schema_a, &key);
        assert_ne!(
            id, alt_id,
            "content bit-flip did not change ObjectId — content-binding broken"
        );
    }

    // ── PROPERTY 4: zone-binding ───────────────────────────────────────
    if zone_a != zone_b {
        let alt_zone_id = ObjectId::new(&input.content, &zone_b, &schema_a, &key);
        assert_ne!(
            id,
            alt_zone_id,
            "different zone ({} vs {}) produced identical ObjectId — \
             zone-binding broken, cross-zone identity forge surface",
            zone_a.as_str(),
            zone_b.as_str()
        );
    }

    // ── PROPERTY 5: schema-binding ─────────────────────────────────────
    if input.schema_a_name != input.schema_b_name {
        let alt_schema_id = ObjectId::new(&input.content, &zone_a, &schema_b, &key);
        assert_ne!(
            id, alt_schema_id,
            "different SchemaId produced identical ObjectId — schema-binding broken"
        );
    }

    // ── PROPERTY 6: key-binding ────────────────────────────────────────
    // Build an alt key that differs in at least one bit. XOR-with-1 on
    // byte 0 guarantees a difference even when the fuzzer-supplied key
    // is all-zero.
    let mut alt_key_bytes = input.key_bytes;
    alt_key_bytes[0] ^= 0x01;
    let alt_key = ObjectIdKey::from_bytes(alt_key_bytes);
    let alt_key_id = ObjectId::new(&input.content, &zone_a, &schema_a, &alt_key);
    assert_ne!(
        id, alt_key_id,
        "different ObjectIdKey produced identical ObjectId — keyed-hash \
         degenerated to unkeyed, breaks per-zone privacy guarantee"
    );

    // ── PROPERTY 7: domain separation from from_unscoped_bytes ─────────
    let unscoped = ObjectId::from_unscoped_bytes(&input.content);
    assert_ne!(
        id, unscoped,
        "scoped ObjectId::new collided with from_unscoped_bytes — domain \
         tag b\"FCP2-OBJECT-V2\" vs b\"FCP2-CONTENT-V2\" lost"
    );

    // ── PROPERTY 8: parse_prefixed round-trip ──────────────────────────
    let prefixed = id.to_prefixed_string();
    let parsed = ObjectId::parse_prefixed(&prefixed)
        .expect("to_prefixed_string output MUST parse back via parse_prefixed");
    assert_eq!(
        id, parsed,
        "parse_prefixed(to_prefixed_string(id)) ≠ id — display/parse non-identity"
    );
});

/// Hand-crafted regression anchor for the keyed-vs-unscoped domain-separation
/// property. The fuzzer would only stumble onto an empty-content collision by
/// chance; we anchor the explicit "empty content under a benign zone/schema
/// MUST NOT collide with from_unscoped_bytes(empty)" case so a regression that
/// drops the domain tag (or the keyed-hash) trips on every run, not only on
/// fuzz-discovered inputs.
fn assert_domain_separation_anchored() {
    let key = ObjectIdKey::from_bytes([0u8; 32]);
    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.fuzz", "Anchor", Version::new(1, 0, 0));

    let scoped_empty = ObjectId::new(b"", &zone, &schema, &key);
    let unscoped_empty = ObjectId::from_unscoped_bytes(b"");
    assert_ne!(
        scoped_empty, unscoped_empty,
        "ObjectId::new(empty) collided with from_unscoped_bytes(empty) — \
         keyed-hash domain separation regression: an attacker could promote \
         an unscoped content hash into a security-object identity"
    );

    // Anchor: schema-binding distinguishes the canonical separator collision
    // pair documented at lib.rs:115-122 (length-prefixing fix). Two SchemaIds
    // whose canonical strings would have collided pre-fix MUST hash distinct.
    let schema_collision_a = SchemaId {
        namespace: "a:b".to_string(),
        name: "c".to_string(),
        version: Version::new(1, 0, 0),
    };
    let schema_collision_b = SchemaId {
        namespace: "a".to_string(),
        name: "b:c".to_string(),
        version: Version::new(1, 0, 0),
    };
    let id_a = ObjectId::new(b"x", &zone, &schema_collision_a, &key);
    let id_b = ObjectId::new(b"x", &zone, &schema_collision_b, &key);
    assert_ne!(
        id_a, id_b,
        "ObjectId::new bound to a separator-aliasing SchemaId pair — \
         schema-hash length-prefixing regression (mzi9x)"
    );

    // Anchor: keyed-hash actually keys. With identical inputs across all
    // four mix slots except the key, ids MUST differ — guards against a
    // regression that swaps blake3::Hasher::new_keyed for new().
    let key_alt = ObjectIdKey::from_bytes([0xFFu8; 32]);
    let id_k0 = ObjectId::new(b"payload", &zone, &schema, &key);
    let id_k1 = ObjectId::new(b"payload", &zone, &schema, &key_alt);
    assert_ne!(
        id_k0, id_k1,
        "ObjectId::new ignored the ObjectIdKey — keyed-hash regression. \
         Per-zone privacy guarantee against dictionary attacks would break."
    );
}
