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
//! Field-order note: `to_canonical_cbor` sorts map keys by their
//! canonical CBOR encoding bytes (RFC 8949 §4.2.1, length-then-bytes).
//! That gives `chain` (5), `taint` (5), `elevated` (8), `origin_zone`
//! (11) in that order — NOT alphabetical. `taint` serializes as the
//! string `"Untainted"` because `TaintLevel` derives `Serialize` with
//! the variant name as-is.
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

const Z_OWNER: &str = "z:owner";
const Z_PRIVATE: &str = "z:private";
const Z_WORK: &str = "z:work";
const Z_PROJECT: &str = "z:project:demo";
const Z_COMMUNITY: &str = "z:community";
const Z_PUBLIC: &str = "z:public";

/// Common prefix for every `Provenance::new(_)` canonical encoding —
/// the four-entry map header plus the `chain`, `taint`, and `elevated`
/// fields, which do not depend on the zone. Only the `origin_zone`
/// suffix differs.
///
/// Decoding:
///   `a4`                    map(4)
///   `65 6368 6169 6e`       text(5) "chain"
///   `80`                    array(0)
///   `65 7461 696e 74`       text(5) "taint"
///   `69 556e 7461 696e 7465 64` text(9) "Untainted"
///   `68 656c 6576 6174 6564` text(8) "elevated"
///   `f4`                    false
///   `6b 6f72 6967 696e 5f7a 6f6e 65` text(11) "origin_zone"
const PROVENANCE_PREFIX_HEX: &str =
    "a465636861696e80657461696e7469556e7461696e74656468656c657661746564f46b6f726967696e5f7a6f6e65";

fn zone(id: &str) -> ZoneId {
    ZoneId::try_from(id.to_string())
        .unwrap_or_else(|err| panic!("zone id {id:?} must validate: {err}"))
}

/// Compose `<prefix>` + text-string-encoded `origin_zone` value.
/// The CBOR text string head is `0x60 + len` for `len <= 23`.
fn expected_hex(zone_id: &str) -> String {
    let z_bytes = zone_id.as_bytes();
    let len = z_bytes.len();
    assert!(len <= 23, "test zones MUST fit in a single-byte CBOR head");
    let head = 0x60u8 | (len as u8);
    format!(
        "{PROVENANCE_PREFIX_HEX}{:02x}{}",
        head,
        hex::encode(z_bytes)
    )
}

/// Helper: encode → assert pinned bytes → decode → assert structural
/// equality → re-encode → assert idempotence.
fn assert_provenance_golden(zone_id: &str) {
    let prov = Provenance::new(zone(zone_id));

    // Property 1 + 2: encode is byte-stable AND matches pin.
    let bytes =
        to_canonical_cbor(&prov).unwrap_or_else(|err| panic!("encode {zone_id} failed: {err}"));
    let bytes2 =
        to_canonical_cbor(&prov).unwrap_or_else(|err| panic!("re-encode {zone_id} failed: {err}"));
    assert_eq!(
        bytes, bytes2,
        "Provenance::new({zone_id}) canonical CBOR is non-deterministic"
    );
    let actual_hex = hex::encode(&bytes);
    let expected = expected_hex(zone_id);
    assert_eq!(
        actual_hex, expected,
        "GOLDEN REGRESSION: Provenance::new({zone_id:?}) canonical CBOR drift\n  \
         actual:   {actual_hex}\n  expected: {expected}"
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
    assert_provenance_golden(Z_OWNER);
}

#[test]
fn provenance_new_private_canonical_cbor_pinned() {
    assert_provenance_golden(Z_PRIVATE);
}

#[test]
fn provenance_new_work_canonical_cbor_pinned() {
    assert_provenance_golden(Z_WORK);
}

#[test]
fn provenance_new_project_canonical_cbor_pinned() {
    assert_provenance_golden(Z_PROJECT);
}

#[test]
fn provenance_new_community_canonical_cbor_pinned() {
    assert_provenance_golden(Z_COMMUNITY);
}

#[test]
fn provenance_new_public_canonical_cbor_pinned() {
    assert_provenance_golden(Z_PUBLIC);
}

#[test]
fn provenance_new_pinned_prefix_is_zone_independent() {
    // The PROVENANCE_PREFIX_HEX assumption that follows from
    // canonical-CBOR encoding is verified here: every
    // Provenance::new(_) MUST share the same prefix and differ only
    // in the trailing origin_zone bytes.
    let zones = [Z_OWNER, Z_PRIVATE, Z_WORK, Z_PROJECT, Z_COMMUNITY, Z_PUBLIC];
    for z in zones {
        let bytes = to_canonical_cbor(&Provenance::new(zone(z))).expect("encode");
        let actual_hex = hex::encode(&bytes);
        assert!(
            actual_hex.starts_with(PROVENANCE_PREFIX_HEX),
            "{z}: encoding does not start with the canonical Provenance prefix\n  \
             actual: {actual_hex}\n  prefix: {PROVENANCE_PREFIX_HEX}"
        );
    }
}

#[test]
fn provenance_new_pinned_bytes_are_pairwise_distinct() {
    // Different zones MUST produce different canonical bytes — this is
    // the invariant that makes content-addressing distinguish zones.
    let zones = [Z_OWNER, Z_PRIVATE, Z_WORK, Z_PROJECT, Z_COMMUNITY, Z_PUBLIC];
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
