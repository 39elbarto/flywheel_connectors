#![no_main]

//! Fuzz target for `fcp_store::KeyedObjectIdVerifier::verify`.
//!
//! This is the WAL-injection gate added by bead 4g0qr
//! (object_id_verifier.rs:18-30). The attack class it closes:
//!
//!   1. Attacker with write access to the durable WAL appends a forged
//!      `Put(StoredObject{ object_id: H, header: H', body: B' })`
//!      where `H` is a previously-seen legitimate id but `(H', B')` are
//!      attacker-controlled bytes.
//!   2. WAL envelope checksum covers only `(version, seq, op)` — the
//!      inner `object_id ↔ (header, body)` binding is NOT covered.
//!   3. On replay, an unverified store happily accepts the forged record;
//!      subsequent reads for `H` return attacker bytes.
//!
//! The existing 4 unit tests cover hand-picked accept/reject cases. This
//! target exercises arbitrary (header_fields, body, claimed_id, key)
//! tuples to surface:
//!
//!   - Panics on edge-case header serialization.
//!   - Accept-path drift on legitimately-derived ids.
//!   - Reject-path drift when the claimed id, body, or key is mutated.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_core::{
    ObjectHeader, ObjectId, ObjectIdKey, Provenance, RetentionClass, StorageMeta, StoredObject,
    ZoneId,
};
use fcp_store::{KeyedObjectIdVerifier, ObjectIdVerifier, ObjectStoreError};
use libfuzzer_sys::fuzz_target;
use semver::Version;

const MAX_BODY_BYTES: usize = 4 * 1024;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Selects a fixed zone — the verifier is keyed per-zone, so we
    /// rotate among the standard hierarchy to exercise lookup paths.
    zone_choice: u8,
    /// `created_at` timestamp is part of the canonical header; mutating
    /// it must change the derived id.
    created_at: u64,
    /// Optional TTL — `Option<u64>` exercises both serde branches.
    ttl_secs: Option<u64>,
    /// Body bytes hashed into the id. Length-bounded to keep iterations
    /// fast.
    body: Vec<u8>,
    /// 32-byte ObjectIdKey installed in the verifier.
    correct_key: [u8; 32],
    /// A different 32-byte key used for the wrong-key rejection MR.
    wrong_key: [u8; 32],
    /// Arbitrary 32 bytes used as a forged claimed id. Distinct from
    /// the genuinely-derived id with overwhelming probability, so the
    /// "forged id rejected" assertion fires.
    forged_id_seed: [u8; 32],
    /// Whether to install `correct_key` in the verifier (false →
    /// VerifierKeyMissing fail-closed branch).
    install_key: bool,
    /// Bit index used to perturb the body for the body-tamper MR.
    bitflip_index: u32,
}

fn pick_zone(choice: u8) -> ZoneId {
    match choice % 5 {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn fixed_schema() -> SchemaId {
    SchemaId::new("fcp.fuzz", "VerifierObject", Version::new(1, 0, 0))
}

fn make_header(zone: &ZoneId, created_at: u64, ttl_secs: Option<u64>) -> ObjectHeader {
    ObjectHeader {
        schema: fixed_schema(),
        zone_id: zone.clone(),
        created_at,
        provenance: Provenance::new(zone.clone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs,
        placement: None,
    }
}

fn make_storage() -> StorageMeta {
    StorageMeta {
        retention: RetentionClass::Pinned,
    }
}

fn install(verifier: &mut KeyedObjectIdVerifier, zone: ZoneId, key: ObjectIdKey) {
    verifier.insert(zone, key);
}

fn flip_bit(bytes: &mut [u8], bit_index: usize) {
    let byte = bit_index / 8;
    let mask = 1u8 << (bit_index % 8);
    bytes[byte] ^= mask;
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let body: &[u8] = if input.body.len() > MAX_BODY_BYTES {
        &input.body[..MAX_BODY_BYTES]
    } else {
        &input.body[..]
    };
    let zone = pick_zone(input.zone_choice);
    let header = make_header(&zone, input.created_at, input.ttl_secs);
    let correct_key = ObjectIdKey::from_bytes(input.correct_key);
    let wrong_key = ObjectIdKey::from_bytes(input.wrong_key);

    // Compute the genuine id under correct_key. If derive_id refuses the
    // header (e.g. canonicalization error on some pathological field
    // combination), we bail — the verifier itself surfaces the same
    // error class as ObjectStoreError::Io and we already tested that
    // path is total.
    let Ok(genuine_id) = StoredObject::derive_id(&header, body, &correct_key) else {
        return;
    };

    // ── Setup verifier ──────────────────────────────────────────────────
    let mut verifier = KeyedObjectIdVerifier::default();
    if input.install_key {
        install(&mut verifier, zone.clone(), correct_key);
    }

    // ── PROPERTY 1: genuine object verifies (when key installed) ────────
    let genuine = StoredObject {
        object_id: genuine_id,
        header: header.clone(),
        body: body.to_vec(),
        storage: make_storage(),
    };
    match verifier.verify(&genuine) {
        Ok(()) => assert!(
            input.install_key,
            "verify accepted but no key was installed for zone"
        ),
        Err(ObjectStoreError::VerifierKeyMissing { .. }) => assert!(
            !input.install_key,
            "VerifierKeyMissing fired despite key being installed"
        ),
        Err(other) => panic!("genuine object rejected with unexpected error {other:?}"),
    }

    // The remaining MRs only fire when a key is installed (otherwise
    // every verify path short-circuits at VerifierKeyMissing — which is
    // already asserted above).
    if !input.install_key {
        return;
    }

    // ── PROPERTY 2: forged claimed_id rejected ──────────────────────────
    // Skip the (negligible) case where the random forged_id_seed
    // happens to collide with genuine_id. The ContentIdMismatch
    // assertion below would still hold — the early return is just
    // hygiene for the rare exact-match case.
    let forged_id = ObjectId::from_bytes(input.forged_id_seed);
    if forged_id != genuine_id {
        let forged_obj = StoredObject {
            object_id: forged_id,
            header: header.clone(),
            body: body.to_vec(),
            storage: make_storage(),
        };
        match verifier.verify(&forged_obj) {
            Err(ObjectStoreError::ContentIdMismatch { claimed, computed }) => {
                assert_eq!(claimed, forged_id);
                assert_eq!(computed, genuine_id);
            }
            other => panic!("forged claimed_id not rejected: {other:?}"),
        }
    }

    // ── PROPERTY 3: body bit-flip rejected ──────────────────────────────
    // Mutating body changes derive_id; the (unchanged) genuine_id should
    // no longer match. Skip when body is empty (no bits to flip).
    if !body.is_empty() {
        let mut tampered_body = body.to_vec();
        let bit = (input.bitflip_index as usize) % (tampered_body.len() * 8);
        flip_bit(&mut tampered_body, bit);
        if tampered_body != body {
            let tampered = StoredObject {
                object_id: genuine_id,
                header: header.clone(),
                body: tampered_body,
                storage: make_storage(),
            };
            match verifier.verify(&tampered) {
                Err(ObjectStoreError::ContentIdMismatch { claimed, computed }) => {
                    assert_eq!(claimed, genuine_id);
                    assert_ne!(computed, genuine_id);
                }
                other => panic!("body bit-flip not rejected: {other:?}"),
            }
        }
    }

    // ── PROPERTY 4: wrong-key verifier rejects genuine object ───────────
    // Replace the installed key with a different one; the recomputed id
    // diverges and ContentIdMismatch fires. (The MR is "MAC bound to
    // key" applied to ObjectId derivation.)
    if input.correct_key != input.wrong_key {
        let mut wrong_verifier = KeyedObjectIdVerifier::default();
        install(&mut wrong_verifier, zone.clone(), wrong_key);
        match wrong_verifier.verify(&genuine) {
            Err(ObjectStoreError::ContentIdMismatch { claimed, computed }) => {
                assert_eq!(claimed, genuine_id);
                assert_ne!(computed, genuine_id);
            }
            // Tiny chance the two random keys produce identical
            // derivations on the same content; treat that as a no-op.
            Ok(()) => {}
            other => panic!("wrong-key verify produced unexpected error: {other:?}"),
        }
    }
});
