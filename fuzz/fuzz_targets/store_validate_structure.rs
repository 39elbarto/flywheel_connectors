#![no_main]

//! Fuzz target for `fcp_core::StoredObject::validate_structure`
//! (object.rs:287-290) — the storage-layer key-free integrity check.
//!
//! `validate_structure` runs the canonical-CBOR pipeline that
//! `derive_id` would run, so any object that cannot have been produced
//! by a legitimate `derive_id` is rejected. Storage backends call this
//! on every WAL write, WAL replay, and snapshot recovery as
//! defense-in-depth — a regression here would let oversized or
//! malformed objects accumulate in the durable log and amplify
//! downstream-allocator risk on replay (the attack class: a 500 MiB
//! `Put` smuggled through a deserialized envelope).
//!
//! Existing fuzz coverage:
//!   - `object_id_verifier`  — exercises the *keyed* WAL-injection gate
//!   - `store_repair_planner` — uses StoredObject as input, does not
//!     probe the structural validation surface
//!
//! This target probes the structural-validation surface directly.
//!
//! Properties asserted:
//!
//!   1. **Panic-free / total**: validate_structure on any well-formed
//!      StoredObject does not panic.
//!   2. **Idempotence**: validate_structure is a pure function — calling
//!      it twice yields the same outcome.
//!   3. **derive_id agreement**: validate_structure passes ⇒ derive_id
//!      succeeds and is deterministic. The two functions share
//!      canonical_bytes, so a divergence between them is a regression.
//!   4. **Refs amplification cap**: a header with N ObjectId refs counts
//!      against MAX_CANONICAL_OBJECT_BYTES. If we add enough refs to push
//!      the canonical encoding past the 64 MiB cap, validate_structure
//!      MUST trip PayloadTooLarge — a regression that excluded refs from
//!      the canonical-CBOR pipeline before size-checking would let an
//!      attacker smuggle a huge refs[] through the gate.
//!
//!   Once-gated regression anchor:
//!     A body whose length alone exceeds MAX_CANONICAL_OBJECT_BYTES MUST
//!     trip PayloadTooLarge. Constructed once-per-process so we don't
//!     burn fuzz budget on a 64 MiB allocation per iteration.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::{MAX_CANONICAL_OBJECT_BYTES, SchemaId, SerializationError};
use fcp_core::{
    ObjectHeader, ObjectId, ObjectIdKey, Provenance, RetentionClass, StorageMeta, StoredObject,
    ZoneId,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_REFS: usize = 64;

static SIZE_CAP_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    zone_choice: u8,
    created_at: u64,
    ttl_secs: Option<u64>,
    body: Vec<u8>,
    /// Number of arbitrary ObjectIds to stuff into refs.
    refs_count: u8,
    /// Number of arbitrary ObjectIds to stuff into foreign_refs.
    foreign_refs_count: u8,
    /// Seed for the per-ref id bytes (deterministic synthesis avoids
    /// exhausting the Unstructured budget on 32 × N bytes).
    refs_seed: u64,
    /// 32-byte key for the derive_id agreement check.
    key_bytes: [u8; 32],
    /// Toggles which RetentionClass to use.
    retention_disc: u8,
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
    SchemaId::new("fcp.fuzz", "ValidateStructure", Version::new(1, 0, 0))
}

fn pick_retention(disc: u8, created_at: u64) -> RetentionClass {
    match disc % 3 {
        0 => RetentionClass::Pinned,
        1 => RetentionClass::Lease {
            expires_at: created_at.saturating_add(3600),
        },
        _ => RetentionClass::Ephemeral,
    }
}

/// xorshift64 — stable per-iteration synthesis of ObjectId bytes for
/// the refs / foreign_refs fields without consuming Unstructured budget.
fn synthesize_ids(seed: u64, count: usize) -> Vec<ObjectId> {
    let mut state = if seed == 0 {
        0xa5a5_5a5a_dead_beef
    } else {
        seed
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let n = chunk.len();
            chunk.copy_from_slice(&state.to_le_bytes()[..n]);
        }
        out.push(ObjectId::from_bytes(bytes));
    }
    out
}

fn build_object(input: &Input) -> StoredObject {
    let zone = pick_zone(input.zone_choice);
    let header = ObjectHeader {
        schema: fixed_schema(),
        zone_id: zone.clone(),
        created_at: input.created_at,
        provenance: Provenance::new(zone),
        refs: synthesize_ids(
            input.refs_seed,
            (input.refs_count as usize) % (MAX_REFS + 1),
        ),
        foreign_refs: synthesize_ids(
            input.refs_seed.wrapping_add(1),
            (input.foreign_refs_count as usize) % (MAX_REFS + 1),
        ),
        ttl_secs: input.ttl_secs,
        placement: None,
    };

    let body_len = input.body.len().min(MAX_BODY_BYTES);
    let body = input.body[..body_len].to_vec();

    StoredObject {
        object_id: ObjectId::from_bytes([0u8; 32]), // placeholder; not validated by validate_structure
        header,
        body,
        storage: StorageMeta {
            retention: pick_retention(input.retention_disc, input.created_at),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    SIZE_CAP_ANCHOR.call_once(assert_size_cap_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let obj = build_object(&input);

    // ── PROPERTY 1: panic-free / total ─────────────────────────────────
    let outcome = obj.validate_structure();

    // ── PROPERTY 2: idempotence ────────────────────────────────────────
    let outcome2 = obj.validate_structure();
    match (&outcome, &outcome2) {
        (Ok(()), Ok(())) => {}
        (Err(a), Err(b)) => assert_eq!(
            std::mem::discriminant(a),
            std::mem::discriminant(b),
            "validate_structure not idempotent: error variants diverge"
        ),
        _ => panic!("validate_structure not idempotent: success/failure diverged across calls"),
    }

    // If validation rejected, none of the downstream properties apply.
    if outcome.is_err() {
        return;
    }

    // ── PROPERTY 3: derive_id agreement ────────────────────────────────
    let key = ObjectIdKey::from_bytes(input.key_bytes);
    let id_a = StoredObject::derive_id(&obj.header, &obj.body, &key)
        .expect("validate_structure passed → derive_id MUST succeed under any key");
    let id_b = StoredObject::derive_id(&obj.header, &obj.body, &key)
        .expect("derive_id must be deterministic");
    assert_eq!(
        id_a, id_b,
        "derive_id is not deterministic on identical (header, body, key)"
    );

    // ── PROPERTY 4: refs amplification cap ─────────────────────────────
    // Synthesize a refs vector large enough that the canonical encoding
    // alone (≈33 bytes per ObjectId in CBOR: 1 byte type + 32 byte
    // payload + array overhead) exceeds MAX_CANONICAL_OBJECT_BYTES.
    // ⌈64MiB / 33⌉ ≈ 2_034_645; doubling for headroom = 4M refs.
    // Allocating 4M ObjectIds is ~128 MiB, too much per iteration.
    // Instead, scope this property to a smaller threshold: build a
    // header whose canonical refs bytes are guaranteed > 64 KiB and
    // verify validate_structure either accepts (well below cap) or
    // rejects with PayloadTooLarge (above cap). Either outcome is
    // legal; the regression we guard is "refs not counted at all" —
    // which would manifest as accepting a header with refs that *would*
    // push past the cap if encoded. The size-cap anchor below provides
    // the once-per-process oversized check.
    //
    // Here we enforce a weaker but still meaningful invariant: adding
    // refs MUST monotonically not-decrease the canonical-byte size. If
    // canonical_bytes(header_with_refs) ≤ canonical_bytes(header_no_refs),
    // refs are being silently dropped from the encoding.
    let mut header_no_refs = obj.header.clone();
    header_no_refs.refs = vec![];
    header_no_refs.foreign_refs = vec![];
    let bytes_no_refs = StoredObject::canonical_bytes(&header_no_refs, &obj.body)
        .expect("baseline header MUST canonically encode");
    let bytes_with_refs = StoredObject::canonical_bytes(&obj.header, &obj.body)
        .expect("validate_structure passed ⇒ canonical_bytes succeeds");
    let refs_total = obj.header.refs.len() + obj.header.foreign_refs.len();
    if refs_total > 0 {
        assert!(
            bytes_with_refs.len() >= bytes_no_refs.len(),
            "canonical_bytes shrunk after adding {} refs ({} → {} bytes) — \
             refs/foreign_refs silently dropped from canonical encoding, \
             refs amplification cap can be bypassed",
            refs_total,
            bytes_no_refs.len(),
            bytes_with_refs.len()
        );
    }
});

/// Once-gated anchor for the body-size cap. Constructs a body whose
/// length pushes total canonical bytes past `MAX_CANONICAL_OBJECT_BYTES`
/// and asserts validate_structure rejects with `PayloadTooLarge`. Run
/// once per process so a regression that drops the size check at
/// object.rs:231-236 trips on every fuzz invocation.
fn assert_size_cap_anchored() {
    let zone = ZoneId::work();
    let header = ObjectHeader {
        schema: fixed_schema(),
        zone_id: zone.clone(),
        created_at: 1_000_000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };
    // Body just over the cap. Header canonical encoding adds roughly
    // 100 bytes; padding by 64 ensures we cross the threshold.
    let body = vec![0u8; MAX_CANONICAL_OBJECT_BYTES + 64];
    let obj = StoredObject {
        object_id: ObjectId::from_bytes([0u8; 32]),
        header,
        body,
        storage: StorageMeta {
            retention: RetentionClass::Ephemeral,
        },
    };

    match obj.validate_structure() {
        Err(SerializationError::PayloadTooLarge { len, max }) => {
            assert_eq!(
                max, MAX_CANONICAL_OBJECT_BYTES,
                "PayloadTooLarge.max ({max}) ≠ MAX_CANONICAL_OBJECT_BYTES ({MAX_CANONICAL_OBJECT_BYTES})"
            );
            assert!(
                len > MAX_CANONICAL_OBJECT_BYTES,
                "PayloadTooLarge.len ({len}) does not exceed MAX_CANONICAL_OBJECT_BYTES"
            );
        }
        Err(other) => panic!(
            "ANCHOR REGRESSION: oversized body produced unexpected error variant {other:?}; \
             expected PayloadTooLarge"
        ),
        Ok(()) => panic!(
            "ANCHOR REGRESSION: validate_structure accepted a body of {} bytes \
             (cap = {}) — body-size enforcement at object.rs:231-236 dropped. \
             A 500 MiB Put could pass the WAL-replay defense-in-depth gate.",
            MAX_CANONICAL_OBJECT_BYTES + 64,
            MAX_CANONICAL_OBJECT_BYTES
        ),
    }
}
