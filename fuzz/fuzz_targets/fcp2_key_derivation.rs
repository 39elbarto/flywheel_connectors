#![no_main]

//! Fuzz target for `Fcp2KeyDerivation` domain separation + HKDF
//! determinism (hkdf.rs:144-254).
//!
//! `Fcp2KeyDerivation` builds the HKDF `info` field using a
//! length-prefixed framing scheme so variable-length parts cannot
//! collide via simple concatenation. Each derivation method also
//! prepends its own static label (`FCP2-ZONE-KEY`, `FCP2-OBJECTID-KEY`,
//! `FCP2-SESSION`, `FCP2-MAC`) so the four key types live in disjoint
//! HKDF output spaces.
//!
//! NOT directly fuzzed: every `Fcp2KeyDerivation::*` function and the
//! `hkdf_sha256` / `hkdf_sha256_array` free functions only have
//! `cargo test` smoke coverage today.
//!
//! A regression that:
//!   - dropped the static label from `framed_info` would let a zone
//!     key collide with an `ObjectId` key for the same zone — content
//!     addressing and zone encryption would share key material.
//!   - replaced length-prefix framing with naive concatenation would
//!     make `(km, zid="AB"||"CD")` collide with `(km, zid="ABCD")` —
//!     an attacker who can split a zone-id boundary recovers another
//!     zone's key.
//!   - swapped Send/Recv labels would let the responder's TX key be
//!     used to authenticate frames in the wrong direction.
//!
//! Properties asserted:
//!
//!   1. **Determinism**: each derivation method is pure — repeated
//!      calls on the same inputs return byte-equal output.
//!   2. **Inter-purpose separation**: for non-trivial inputs,
//!      `derive_zone_key(km, zid) != derive_objectid_key(km, zid)`.
//!   3. **Direction separation (session)**: for the same
//!      `(shared_secret, session_id)`, `Send` and `Recv` derive
//!      different 32-byte keys.
//!   4. **MAC purpose separation**: `derive_mac_key` for the three
//!      purposes Frame / Header / Auth produces three pairwise-distinct
//!      keys.
//!   5. **Framing collision resistance**: `derive_zone_key(km, zid)`
//!      with the SAME zone_id but different `km` splits (or vice
//!      versa) produces different keys — verified by comparing
//!      `(km1, zid1)` vs `(km1', zid1')` where `km1||zid1 ==
//!      km1'||zid1'` but the boundary moved.
//!   6. **hkdf_sha256 agreement**: `hkdf_sha256_array::<32>` matches
//!      `HkdfSha256::new(salt, ikm).expand_to_array(info)`.
//!
//!   Once-gated anchors verify every domain label and the
//!   length-prefix framing collision-resistance on a hand-picked
//!   boundary split.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::hkdf::{
    Fcp2KeyDerivation, HkdfSha256, MacKeyPurpose, SessionDirection, hkdf_sha256_array,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static FCP2_KDF_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    key_material: Vec<u8>,
    zone_id: Vec<u8>,
    session_id: Vec<u8>,
    /// Boundary split position used by Property 5 (mod (km||zid).len()).
    boundary_idx: u16,
}

const MAX_FIELD: usize = 256;

fuzz_target!(|data: &[u8]| {
    FCP2_KDF_ANCHOR.call_once(assert_fcp2_kdf_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.key_material.len() > MAX_FIELD
        || input.zone_id.len() > MAX_FIELD
        || input.session_id.len() > MAX_FIELD
        || input.key_material.is_empty()
    {
        // Skip empty key_material (HKDF technically allows it but it's
        // not interesting for separation tests).
        return;
    }

    // ── PROPERTY 1: determinism ─────────────────────────────────────────
    let zone_a = Fcp2KeyDerivation::derive_zone_key(&input.key_material, &input.zone_id)
        .expect("derive_zone_key A");
    let zone_b = Fcp2KeyDerivation::derive_zone_key(&input.key_material, &input.zone_id)
        .expect("derive_zone_key B");
    assert_eq!(
        zone_a.as_bytes(),
        zone_b.as_bytes(),
        "derive_zone_key non-deterministic"
    );

    let oid_a = Fcp2KeyDerivation::derive_objectid_key(&input.key_material, &input.zone_id)
        .expect("derive_objectid_key A");
    let oid_b = Fcp2KeyDerivation::derive_objectid_key(&input.key_material, &input.zone_id)
        .expect("derive_objectid_key B");
    assert_eq!(
        oid_a.as_bytes(),
        oid_b.as_bytes(),
        "derive_objectid_key non-deterministic"
    );

    // ── PROPERTY 2: inter-purpose separation (zone vs objectid) ────────
    assert_ne!(
        zone_a.as_bytes(),
        oid_a.as_bytes(),
        "derive_zone_key collided with derive_objectid_key — domain \
         separation lost (FCP2-ZONE-KEY vs FCP2-OBJECTID-KEY labels)"
    );

    // ── PROPERTY 3: session direction separation ────────────────────────
    let send = Fcp2KeyDerivation::derive_session_key(
        &input.key_material,
        &input.session_id,
        SessionDirection::Send,
    )
    .expect("derive_session_key Send");
    let recv = Fcp2KeyDerivation::derive_session_key(
        &input.key_material,
        &input.session_id,
        SessionDirection::Recv,
    )
    .expect("derive_session_key Recv");
    assert_ne!(
        send.as_bytes(),
        recv.as_bytes(),
        "derive_session_key Send/Recv collided — direction separation lost"
    );

    // ── PROPERTY 4: MAC purpose pairwise separation ─────────────────────
    let mac_frame = Fcp2KeyDerivation::derive_mac_key(&input.key_material, MacKeyPurpose::Frame)
        .expect("derive_mac_key Frame");
    let mac_header = Fcp2KeyDerivation::derive_mac_key(&input.key_material, MacKeyPurpose::Header)
        .expect("derive_mac_key Header");
    let mac_auth = Fcp2KeyDerivation::derive_mac_key(&input.key_material, MacKeyPurpose::Auth)
        .expect("derive_mac_key Auth");
    assert_ne!(
        mac_frame.as_bytes(),
        mac_header.as_bytes(),
        "MAC Frame/Header collided"
    );
    assert_ne!(
        mac_frame.as_bytes(),
        mac_auth.as_bytes(),
        "MAC Frame/Auth collided"
    );
    assert_ne!(
        mac_header.as_bytes(),
        mac_auth.as_bytes(),
        "MAC Header/Auth collided"
    );

    // ── PROPERTY 5: framing collision resistance ───────────────────────
    // Build a single byte buffer = key_material || zone_id and split it
    // at two different positions; if framing is correct the derived
    // keys must differ even though the concatenation is identical.
    let mut concat = input.key_material.clone();
    concat.extend_from_slice(&input.zone_id);
    if concat.len() >= 2 {
        // Original split: |km| / |zid|. Pick a different split.
        let original_split = input.key_material.len();
        // The boundary_idx is bounded so `% (concat.len() - 1)` produces
        // a value in 1..concat.len(); compare against original_split.
        let split2 = 1 + (input.boundary_idx as usize % (concat.len() - 1));
        if split2 != original_split {
            let alt_km = &concat[..split2];
            let alt_zid = &concat[split2..];
            // Skip when the alternative km would be empty (filtered above).
            if !alt_km.is_empty() {
                let alt = Fcp2KeyDerivation::derive_zone_key(alt_km, alt_zid)
                    .expect("derive_zone_key alt split");
                assert_ne!(
                    zone_a.as_bytes(),
                    alt.as_bytes(),
                    "derive_zone_key collided across boundary split — \
                     length-prefix framing in framed_info is broken"
                );
            }
        }
    }

    // ── PROPERTY 6: hkdf_sha256 free-function == HkdfSha256 method ─────
    let info = b"agreement-fuzz-info";
    let arr = hkdf_sha256_array::<32>(None, &input.key_material, info).expect("hkdf_sha256_array");
    let h = HkdfSha256::new(None, &input.key_material);
    let arr2: [u8; 32] = h
        .expand_to_array(info)
        .expect("HkdfSha256::expand_to_array");
    assert_eq!(
        arr, arr2,
        "hkdf_sha256_array diverged from HkdfSha256::new+expand_to_array"
    );
});

/// Once-gated anchors verifying each domain label and length-prefix
/// framing collision resistance on a hand-picked boundary split.
fn assert_fcp2_kdf_anchored() {
    let km = b"FCP2 anchor key material";
    let zid = b"zone-x";

    // (a) Inter-purpose separation on a known input.
    let z = Fcp2KeyDerivation::derive_zone_key(km, zid).expect("ANCHOR: zone");
    let o = Fcp2KeyDerivation::derive_objectid_key(km, zid).expect("ANCHOR: oid");
    assert_ne!(
        z.as_bytes(),
        o.as_bytes(),
        "ANCHOR REGRESSION: zone vs objectid label not separating output"
    );

    // (b) Direction separation on a known input.
    let send = Fcp2KeyDerivation::derive_session_key(km, b"sid", SessionDirection::Send)
        .expect("ANCHOR: send");
    let recv = Fcp2KeyDerivation::derive_session_key(km, b"sid", SessionDirection::Recv)
        .expect("ANCHOR: recv");
    assert_ne!(
        send.as_bytes(),
        recv.as_bytes(),
        "ANCHOR REGRESSION: Send/Recv label not separating output"
    );

    // (c) MAC purpose pairwise separation.
    let f = Fcp2KeyDerivation::derive_mac_key(km, MacKeyPurpose::Frame).expect("ANCHOR: frame");
    let h = Fcp2KeyDerivation::derive_mac_key(km, MacKeyPurpose::Header).expect("ANCHOR: header");
    let a = Fcp2KeyDerivation::derive_mac_key(km, MacKeyPurpose::Auth).expect("ANCHOR: auth");
    assert_ne!(
        f.as_bytes(),
        h.as_bytes(),
        "ANCHOR: Frame vs Header collide"
    );
    assert_ne!(f.as_bytes(), a.as_bytes(), "ANCHOR: Frame vs Auth collide");
    assert_ne!(h.as_bytes(), a.as_bytes(), "ANCHOR: Header vs Auth collide");

    // (d) Framing collision resistance: same byte concat, different split.
    // (km, zid) = ("AB", "CDEF") vs ("ABCD", "EF") — concat is "ABCDEF"
    // in both cases. Without length-prefix framing the HKDF info would
    // be the same; with framing they must derive different keys.
    let k1 = Fcp2KeyDerivation::derive_zone_key(b"AB", b"CDEF").expect("ANCHOR: split AB|CDEF");
    let k2 = Fcp2KeyDerivation::derive_zone_key(b"ABCD", b"EF").expect("ANCHOR: split ABCD|EF");
    assert_ne!(
        k1.as_bytes(),
        k2.as_bytes(),
        "ANCHOR REGRESSION: ('AB','CDEF') and ('ABCD','EF') derive the \
         same zone key — length-prefix framing in framed_info is broken \
         and an attacker who controls the boundary split recovers \
         another zone's key"
    );

    // (e) Determinism — same input → same output.
    let z2 = Fcp2KeyDerivation::derive_zone_key(km, zid).expect("ANCHOR: zone repeat");
    assert_eq!(
        z.as_bytes(),
        z2.as_bytes(),
        "ANCHOR REGRESSION: derive_zone_key not deterministic"
    );
}
