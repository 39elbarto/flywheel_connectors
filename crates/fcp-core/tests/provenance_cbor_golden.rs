//! Golden artifact: pin canonical-CBOR encoding of `Provenance::new(zone)`
//! for the canonical zone set (flywheel_connectors-saa7i).
//!
//! `Provenance::new(zone)` is the seed used by every fresh request and
//! by every `ObjectHeader`. Its canonical-CBOR encoding feeds into
//! content addressing and signing transcripts, so any drift in the
//! encoding silently splits content-address spaces between revisions.
//!
//! This test pins the byte sequence for the six canonical zone seeds:
//! `z:owner`, `z:private`, `z:work`, `z:project:demo`, `z:community`,
//! and `z:public`. A deliberate change to the `Provenance` shape (a
//! new field, a renamed field, a default change) MUST also update the
//! pinned bytes here so the regression is visible in review.
//!
//! Properties verified per zone:
//!   1. `to_canonical_cbor(prov)` is byte-stable across runs.
//!   2. The canonical bytes match the pinned hex constant.
//!   3. `ciborium::from_reader(bytes)` decodes back to a structurally
//!      equal `Provenance` (origin_zone, taint, elevated, chain length,
//!      elevation_token presence).
//!   4. Re-encoding the decoded value yields the original bytes
//!      (idempotence under encode∘decode).

use fcp_cbor::to_canonical_cbor;
use fcp_core::{Provenance, TaintLevel, ZoneId};

const Z_OWNER_HEX: &str = "z:owner";
const Z_PRIVATE_HEX: &str = "z:private";
const Z_WORK_HEX: &str = "z:work";
const Z_PROJECT_HEX: &str = "z:project:demo";
const Z_COMMUNITY_HEX: &str = "z:community";
const Z_PUBLIC_HEX: &str = "z:public";

fn zone(id: &str) -> ZoneId {
    ZoneId::try_from(id.to_string())
        .unwrap_or_else(|err| panic!("zone id {id:?} must validate: {err}"))
}

/// Helper: encode → assert pinned bytes → decode → assert structural
/// equality → re-encode → assert idempotence.
fn assert_provenance_golden(zone_id: &str, expected_hex: &str) {
    let prov = Provenance::new(zone(zone_id));

    // Property 1 + 2: encode is byte-stable AND matches pin.
    let bytes = to_canonical_cbor(&prov)
        .unwrap_or_else(|err| panic!("encode {zone_id} failed: {err}"));
    let bytes2 = to_canonical_cbor(&prov)
        .unwrap_or_else(|err| panic!("re-encode {zone_id} failed: {err}"));
    assert_eq!(
        bytes, bytes2,
        "Provenance::new({zone_id}) canonical CBOR is non-deterministic"
    );
    let actual_hex = hex::encode(&bytes);
    assert_eq!(
        actual_hex, expected_hex,
        "GOLDEN REGRESSION: Provenance::new({zone_id:?}) canonical CBOR drift\n  \
         actual:   {actual_hex}\n  expected: {expected_hex}"
    );

    // Property 3: structural equality after decode.
    let decoded: Provenance = ciborium::from_reader(&bytes[..])
        .unwrap_or_else(|err| panic!("decode {zone_id} failed: {err}"));
    assert_eq!(
        decoded.origin_zone.as_str(),
        zone_id,
        "{zone_id}: origin_zone changed across round-trip"
    );
    assert_eq!(
        decoded.taint,
        TaintLevel::Untainted,
        "{zone_id}: taint MUST default to Untainted on Provenance::new"
    );
    assert!(
        !decoded.elevated,
        "{zone_id}: elevated MUST default to false on Provenance::new"
    );
    assert!(
        decoded.chain.is_empty(),
        "{zone_id}: chain MUST default to empty on Provenance::new"
    );
    assert!(
        decoded.elevation_token.is_none(),
        "{zone_id}: elevation_token MUST default to None on Provenance::new"
    );

    // Property 4: encode∘decode idempotent.
    let re_encoded = to_canonical_cbor(&decoded)
        .unwrap_or_else(|err| panic!("re-encode decoded {zone_id} failed: {err}"));
    assert_eq!(
        bytes, re_encoded,
        "{zone_id}: encode→decode→encode not idempotent"
    );
}

#[test]
fn provenance_new_owner_canonical_cbor_pinned() {
    // CBOR map {origin_zone: "z:owner", chain: [], taint: 0, elevated: false}
    // sorted lex by key bytes:
    //   "chain" (5)        → 0x65 "chain"  → []                  (0x80)
    //   "elevated" (8)     → 0x68 "elevated" → false             (0xf4)
    //   "origin_zone"(11)  → 0x6b "origin_zone" → "z:owner"      (0x67 …)
    //   "taint" (5)        → 0x65 "taint" → "untainted"          (0x69 …)
    // Outer map header for 4 entries: 0xa4.
    assert_provenance_golden(
        Z_OWNER_HEX,
        "a46563686169648068656c6576617465\
         64f46b6f726967696e5f7a6f6e656777\
         3a6f776e65726574\
         61696e7469756e7461696e746564",
    );
}

#[test]
fn provenance_new_private_canonical_cbor_pinned() {
    assert_provenance_golden(
        Z_PRIVATE_HEX,
        "a46563686169648068656c6576617465\
         64f46b6f726967696e5f7a6f6e656970\
         3a707269766174656574\
         61696e7469756e7461696e746564",
    );
}

#[test]
fn provenance_new_work_canonical_cbor_pinned() {
    assert_provenance_golden(
        Z_WORK_HEX,
        "a46563686169648068656c6576617465\
         64f46b6f726967696e5f7a6f6e6566\
         3a776f726b6574\
         61696e7469756e7461696e746564",
    );
}

#[test]
fn provenance_new_project_canonical_cbor_pinned() {
    assert_provenance_golden(
        Z_PROJECT_HEX,
        "a46563686169648068656c6576617465\
         64f46b6f726967696e5f7a6f6e656e7a\
         3a70726f6a6563743a64656d6f6574\
         61696e7469756e7461696e746564",
    );
}

#[test]
fn provenance_new_community_canonical_cbor_pinned() {
    assert_provenance_golden(
        Z_COMMUNITY_HEX,
        "a46563686169648068656c6576617465\
         64f46b6f726967696e5f7a6f6e656c7a\
         3a636f6d6d756e6974796574\
         61696e7469756e7461696e746564",
    );
}

#[test]
fn provenance_new_public_canonical_cbor_pinned() {
    assert_provenance_golden(
        Z_PUBLIC_HEX,
        "a46563686169648068656c6576617465\
         64f46b6f726967696e5f7a6f6e6568\
         3a7075626c69636574\
         61696e7469756e7461696e746564",
    );
}

#[test]
fn provenance_new_pinned_bytes_are_pairwise_distinct() {
    // Different zones MUST produce different canonical bytes — this is
    // the invariant that makes content-addressing distinguish zones.
    let zones = [
        Z_OWNER_HEX,
        Z_PRIVATE_HEX,
        Z_WORK_HEX,
        Z_PROJECT_HEX,
        Z_COMMUNITY_HEX,
        Z_PUBLIC_HEX,
    ];
    let encodings: Vec<Vec<u8>> = zones
        .iter()
        .map(|z| to_canonical_cbor(&Provenance::new(zone(z))).expect("encode"))
        .collect();
    for i in 0..encodings.len() {
        for j in (i + 1)..encodings.len() {
            assert_ne!(
                encodings[i], encodings[j],
                "zones {} and {} canonical-CBOR collide",
                zones[i], zones[j]
            );
        }
    }
}
