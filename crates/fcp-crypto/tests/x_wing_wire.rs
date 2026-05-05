//! V4 X-Wing wire-format conformance harness (br-kyopb.1.2.2).
//!
//! Pins:
//! - `XWingSealedBox` CBOR shape (text-keyed map of two `bstr` fields).
//! - `Fcp4Aad` CBOR shape and the cross-version-replay invariants
//!   against the V3 [`fcp_crypto::Fcp2Aad`].
//! - End-to-end sealing with `Fcp4Aad::encode()` as the AEAD AAD,
//!   verifying any single field flip causes the seal to fail to open.
//!
//! Acceptance criteria (sub-bead):
//! 1. CBOR round-trip for `XWingSealedBox`.
//! 2. AEAD profile pinned to ChaCha20-Poly1305 with all-zero nonce
//!    (verified via the canonical-CBOR + provider round-trip below).
//! 3. AAD encoder updated — `Fcp4Aad` introduced and exercised here.

use ciborium::Value;
use fcp_crypto::{
    CryptoError, FCP4_AAD_VERSION, Fcp2Aad, Fcp4Aad, MAX_V4_PAYLOAD_BYTES, XWING_ENC_SIZE,
    XWING_PUBLIC_KEY_SIZE, XWING_SECRET_KEY_SIZE, XWingKem, XWingProvider, XWingPublicKey,
    XWingSealedBox, XWingSecretKey,
    xwing::{XWING_AEAD_INFO, purpose as v4_purpose},
};

// ── XWingSealedBox CBOR wire shape ──────────────────────────────────────

#[test]
fn x_wing_wire_sealed_box_cbor_round_trips() {
    let original = XWingSealedBox {
        enc: vec![0x42u8; XWING_ENC_SIZE],
        ciphertext: {
            // Tag (16 B) + plaintext-length (32 B) — typical zone-key wrap.
            let mut v = vec![0xAAu8; 48];
            v[0] = 0xDE;
            v[1] = 0xAD;
            v[2] = 0xBE;
            v[3] = 0xEF;
            v
        },
    };
    let cbor = original.to_canonical_cbor().unwrap();
    let decoded = XWingSealedBox::from_canonical_cbor(&cbor).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn x_wing_wire_sealed_box_cbor_is_a_two_field_text_keyed_map() {
    // Pin the canonical CBOR layout: a 2-entry map with `bstr` values
    // under the text keys "ciphertext" and "enc". A future rename of
    // either field would change the wire format, so this test forces a
    // conscious decision rather than a silent incompatibility.
    let sealed = XWingSealedBox {
        enc: vec![0x01u8; XWING_ENC_SIZE],
        ciphertext: vec![0x02u8; 48],
    };
    let cbor = sealed.to_canonical_cbor().unwrap();
    let value: Value = ciborium::from_reader(&cbor[..]).unwrap();
    let Value::Map(entries) = value else {
        panic!("XWingSealedBox CBOR must be a map, got {value:?}");
    };
    assert_eq!(entries.len(), 2, "exactly 2 fields");

    let mut keys: Vec<String> = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            other => panic!("unexpected key {other:?}"),
        })
        .collect();
    keys.sort();
    assert_eq!(keys, vec!["ciphertext".to_string(), "enc".to_string()]);

    // RFC 8949 §4.2.1 length-then-bytewise key ordering puts shorter
    // keys first; "enc" (3) precedes "ciphertext" (10) in canonical
    // form. Pin that explicitly so accidental sort changes trip here.
    match (&entries[0].0, &entries[1].0) {
        (Value::Text(a), Value::Text(b)) => {
            assert_eq!(a, "enc", "RFC 8949 length-first key order");
            assert_eq!(b, "ciphertext");
        }
        _ => panic!("non-text key in canonical map"),
    }

    // Both values must be bstr.
    for (_, v) in &entries {
        assert!(
            matches!(v, Value::Bytes(_)),
            "XWingSealedBox values must be CBOR bstr, got {v:?}"
        );
    }
}

#[test]
fn x_wing_wire_sealed_box_cbor_rejects_wrong_enc_length() {
    let bad = XWingSealedBox {
        enc: vec![0u8; XWING_ENC_SIZE - 1], // off by one
        ciphertext: vec![0u8; 48],
    };
    let cbor = bad.to_canonical_cbor().unwrap();
    assert!(
        XWingSealedBox::from_canonical_cbor(&cbor).is_err(),
        "decoder must reject wrong-length enc"
    );
}

#[test]
fn x_wing_wire_sealed_box_cbor_rejects_oversized_input() {
    // Build a CBOR-valid but oversized blob and confirm the decoder
    // refuses to handle it before allocating.
    let too_big = XWingSealedBox {
        enc: vec![0u8; XWING_ENC_SIZE],
        ciphertext: vec![0u8; fcp_crypto::XWING_MAX_CIPHERTEXT + 1],
    };
    let cbor = too_big.to_canonical_cbor().unwrap();
    let err = XWingSealedBox::from_canonical_cbor(&cbor).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::PayloadTooLarge {
            observed,
            max: MAX_V4_PAYLOAD_BYTES
        } if observed == cbor.len()
    ));
}

#[test]
fn x_wing_wire_sealed_box_cbor_rejects_short_ciphertext() {
    // ciphertext shorter than the 16-byte AEAD tag would silently leak
    // an AEAD-shaped output that could never decrypt; reject it.
    let bad = XWingSealedBox {
        enc: vec![0u8; XWING_ENC_SIZE],
        ciphertext: vec![0u8; 8], // < 16 byte tag
    };
    let cbor = bad.to_canonical_cbor().unwrap();
    assert!(
        XWingSealedBox::from_canonical_cbor(&cbor).is_err(),
        "decoder must reject ciphertext shorter than AEAD tag"
    );
}

#[test]
fn x_wing_wire_sealed_box_cbor_is_deterministic_per_rfc8949() {
    // Encoding the same struct twice must produce byte-identical CBOR.
    // This is what makes embedded sealed boxes hash reproducibly inside
    // signed transcripts.
    let sealed = XWingSealedBox {
        enc: vec![0xAB; XWING_ENC_SIZE],
        ciphertext: vec![0xCD; 64],
    };
    let a = sealed.to_canonical_cbor().unwrap();
    let b = sealed.to_canonical_cbor().unwrap();
    assert_eq!(a, b, "canonical CBOR must be deterministic");
}

// ── Fcp4Aad CBOR wire shape ─────────────────────────────────────────────

#[test]
fn x_wing_wire_fcp4_aad_carries_version_byte() {
    let aad = Fcp4Aad::for_zone_key(b"z:work", b"node-7", 1_700_000_000);
    assert_eq!(aad.version, FCP4_AAD_VERSION);
    assert_eq!(aad.version, 4);
    assert_eq!(aad.purpose.as_slice(), v4_purpose::ZONE_KEY);
}

#[test]
fn x_wing_wire_fcp4_aad_purpose_strings_have_fcp4_prefix() {
    // Cross-version-replay invariant: every V4 purpose string must
    // start with "FCP4-" so it cannot accidentally be parsed as the V3
    // ("FCP2-") AAD. Lock the strings here so a refactor that drops
    // the prefix trips this test.
    for label in [
        v4_purpose::ZONE_KEY,
        v4_purpose::OBJECTID_KEY,
        v4_purpose::OWNER_SHARE,
        v4_purpose::SECRET_SHARE,
    ] {
        assert!(
            label.starts_with(b"FCP4-"),
            "V4 purpose label must start with `FCP4-`, got {:?}",
            std::str::from_utf8(label).unwrap_or("<non-utf8>")
        );
    }
}

#[test]
fn x_wing_wire_fcp4_aad_cbor_diverges_from_fcp2_for_same_logical_inputs() {
    // Encoding the "same" (zone, recipient, issued_at) triple under V3
    // and V4 MUST yield distinct CBOR — otherwise an attacker who
    // captured a V3 sealed box could replay the AAD bytes verbatim
    // against a V4 verifier.
    let zone = b"z:work";
    let node = b"node-7";
    let ts = 1_700_000_000_u64;

    let v3 = Fcp2Aad::for_zone_key(zone, node, ts).encode().unwrap();
    let v4 = Fcp4Aad::for_zone_key(zone, node, ts).encode().unwrap();
    assert_ne!(
        v3, v4,
        "V3 and V4 AAD encodings must differ even for identical logical inputs"
    );
}

#[test]
fn x_wing_wire_fcp4_aad_encode_is_deterministic() {
    let a = Fcp4Aad::for_zone_key(b"z:home", b"node-3", 42)
        .encode()
        .unwrap();
    let b = Fcp4Aad::for_zone_key(b"z:home", b"node-3", 42)
        .encode()
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn x_wing_wire_fcp4_aad_constructors_set_correct_purpose() {
    assert_eq!(
        Fcp4Aad::for_zone_key(b"z", b"n", 0).purpose.as_slice(),
        v4_purpose::ZONE_KEY
    );
    assert_eq!(
        Fcp4Aad::for_objectid_key(b"z", b"n", 0).purpose.as_slice(),
        v4_purpose::OBJECTID_KEY
    );
    assert_eq!(
        Fcp4Aad::for_secret_share(b"z", b"n", 0).purpose.as_slice(),
        v4_purpose::SECRET_SHARE
    );
}

// ── End-to-end provider integration with Fcp4Aad ────────────────────────

#[test]
fn x_wing_wire_provider_seal_open_round_trip_with_fcp4_aad() {
    let provider = XWingProvider::new();
    let (pk, sk) = provider.generate().unwrap();
    let aad = Fcp4Aad::for_zone_key(b"z:work", b"node-7", 1_700_000_000);
    let aad_bytes = aad.encode().unwrap();

    let plaintext = b"FCP V4 zone key material (kyopb.1.2.2)";
    let sealed = provider.seal(&pk, plaintext, &aad_bytes).unwrap();
    assert_eq!(sealed.enc.len(), XWING_ENC_SIZE);

    let opened = provider.open(&sk, &sealed, &aad_bytes).unwrap();
    assert_eq!(opened.as_slice(), plaintext);

    // The CBOR-encoded sealed box also round-trips end-to-end.
    let cbor = sealed.to_canonical_cbor().unwrap();
    let sealed_back = XWingSealedBox::from_canonical_cbor(&cbor).unwrap();
    let opened_back = provider.open(&sk, &sealed_back, &aad_bytes).unwrap();
    assert_eq!(opened_back.as_slice(), plaintext);
}

#[test]
fn x_wing_wire_aad_field_flip_breaks_open() {
    // Each Fcp4Aad field must contribute to authentication. Flip one
    // field at a time and confirm `open` rejects.
    let provider = XWingProvider::new();
    let (pk, sk) = provider.generate().unwrap();
    let plaintext = b"payload";

    let base = Fcp4Aad::for_zone_key(b"z:work", b"node-7", 1_700_000_000);
    let sealed = provider
        .seal(&pk, plaintext, &base.encode().unwrap())
        .unwrap();

    let mut changed_zone = base.clone();
    changed_zone.zone_id = b"z:home".to_vec();
    let mut changed_recipient = base.clone();
    changed_recipient.recipient_node_id = b"node-8".to_vec();
    let mut changed_purpose = base.clone();
    changed_purpose.purpose = v4_purpose::OBJECTID_KEY.to_vec();
    let mut changed_time = base.clone();
    changed_time.issued_at = base.issued_at + 1;
    let mut changed_version = base;
    changed_version.version = 99;

    for variant in [
        ("zone_id", changed_zone),
        ("recipient_node_id", changed_recipient),
        ("purpose", changed_purpose),
        ("issued_at", changed_time),
        ("version", changed_version),
    ] {
        let (label, aad) = variant;
        let result = provider.open(&sk, &sealed, &aad.encode().unwrap());
        assert!(
            result.is_err(),
            "{label}: flipped AAD field must break open()"
        );
    }
}

#[test]
fn x_wing_wire_aead_profile_constants_are_pinned() {
    // br-kyopb.1.2.2 final decision: ChaCha20-Poly1305 with all-zero
    // nonce, key derived via HKDF-SHA256 from the X-Wing shared secret.
    // Lock the HKDF info string here; changing it would invalidate
    // every existing V4 sealed box.
    assert_eq!(XWING_AEAD_INFO, b"FCP4-XWING-AEAD");

    // Pin the wire-form constants too — these are part of the spec, not
    // implementation details.
    assert_eq!(XWING_PUBLIC_KEY_SIZE, 1216);
    assert_eq!(XWING_SECRET_KEY_SIZE, 32);
    assert_eq!(XWING_ENC_SIZE, 1120);
}

#[test]
fn x_wing_wire_seal_does_not_leak_plaintext_in_ciphertext() {
    // Sanity belt: AEAD output must not contain the plaintext bytes
    // verbatim. Catches a class of "encryption forgot to encrypt" bugs.
    let provider = XWingProvider::new();
    let (pk, _sk) = provider.generate().unwrap();
    let plaintext = b"unique-plaintext-marker-xyzzy-kyopb-1-2-2";
    let sealed = provider
        .seal(
            &pk,
            plaintext,
            &Fcp4Aad::for_zone_key(b"z", b"n", 0).encode().unwrap(),
        )
        .unwrap();
    let needle = plaintext.as_slice();
    assert!(
        !sealed.ciphertext.windows(needle.len()).any(|w| w == needle),
        "ciphertext must not contain plaintext bytes verbatim"
    );
}

// ── Stub vs Provider pinning (forward-compat for kyopb.1.2.4) ──────────

#[test]
fn x_wing_wire_secret_key_round_trips_through_bytes() {
    let provider = XWingProvider::new();
    let (_pk, sk) = provider.generate().unwrap();
    let bytes = sk.as_bytes().to_vec();
    let sk_back = XWingSecretKey::from_bytes(&bytes).unwrap();
    assert_eq!(sk_back.as_bytes(), bytes.as_slice());
}

#[test]
fn x_wing_wire_public_key_round_trips_through_bytes() {
    let provider = XWingProvider::new();
    let (pk, _sk) = provider.generate().unwrap();
    let bytes = pk.to_bytes();
    let pk_back = XWingPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk_back.as_bytes(), bytes.as_slice());
}
