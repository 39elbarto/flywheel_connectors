//! X-Wing KEM round-trip and hybrid-security regression coverage.
//!
//! Complements `xwing_vectors.rs`: that file pins the upstream draft
//! vectors byte-for-byte; this file exercises the FCP wrapper's property
//! surface plus the X-Wing combiner when one hybrid component is assumed
//! compromised.

use fcp_crypto::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, CryptoError, XWING_ENC_SIZE,
    XWING_SECRET_KEY_SIZE, XWingKem, XWingProvider, hkdf_sha256_array, xwing::XWING_AEAD_INFO,
};
use ml_kem::{
    Decapsulate, FromSeed, MlKem768,
    array::{Array, sizes::U64},
};
use proptest::prelude::*;
use serde::Deserialize;
use sha3::{
    Sha3_256, Shake256,
    digest::{Digest, ExtendableOutput, Update, XofReader},
};
use x25519_dalek_v3::{PublicKey, StaticSecret};

#[derive(Debug, Deserialize)]
struct TestVector {
    #[serde(with = "hex::serde")]
    ss: Vec<u8>,
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
    #[serde(with = "hex::serde")]
    ct: Vec<u8>,
}

#[derive(Debug)]
struct Components {
    ss_mlkem: [u8; 32],
    ss_x25519: [u8; 32],
    ct_x25519: [u8; 32],
    pk_x25519: [u8; 32],
}

fn vectors() -> Vec<TestVector> {
    serde_json::from_str(include_str!("data/xwing_test_vectors.json"))
        .expect("xwing_test_vectors.json must parse")
}

fn read_xof<const N: usize>(reader: &mut impl XofReader) -> [u8; N] {
    let mut out = [0u8; N];
    reader.read(&mut out);
    out
}

fn components_from_vector(v: &TestVector) -> Components {
    assert_eq!(v.sk.len(), XWING_SECRET_KEY_SIZE);
    assert_eq!(v.ct.len(), XWING_ENC_SIZE);
    assert_eq!(v.pk.len(), 1216);

    let sk: [u8; XWING_SECRET_KEY_SIZE] = v.sk.as_slice().try_into().unwrap();
    let mut shaker = Shake256::default();
    Update::update(&mut shaker, &sk);
    let mut expanded = shaker.finalize_xof();

    let mlkem_seed: Array<u8, U64> = read_xof::<64>(&mut expanded).into();
    let (mlkem_secret_key, _mlkem_public_key) = MlKem768::from_seed(&mlkem_seed);
    let x25519_secret_key = StaticSecret::from(read_xof::<32>(&mut expanded));

    let ct_mlkem: ml_kem::ml_kem_768::Ciphertext =
        <[u8; 1088]>::try_from(&v.ct[..1088]).unwrap().into();
    let mlkem_shared_secret = mlkem_secret_key.decapsulate(&ct_mlkem);

    let ct_x25519 = <[u8; 32]>::try_from(&v.ct[1088..]).unwrap();
    let pk_x25519 = <[u8; 32]>::try_from(&v.pk[1184..]).unwrap();
    let x25519_shared_secret = x25519_secret_key.diffie_hellman(&PublicKey::from(ct_x25519));

    Components {
        ss_mlkem: array32(mlkem_shared_secret.as_slice()),
        ss_x25519: *x25519_shared_secret.as_bytes(),
        ct_x25519,
        pk_x25519,
    }
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("slice must be 32 bytes")
}

fn x_wing_combiner(
    ss_mlkem: &[u8; 32],
    ss_x25519: &[u8; 32],
    ct_x25519: &[u8; 32],
    pk_x25519: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, ss_mlkem);
    Digest::update(&mut hasher, ss_x25519);
    Digest::update(&mut hasher, ct_x25519);
    Digest::update(&mut hasher, pk_x25519);
    Digest::update(&mut hasher, br"\.//^\");
    array32(&hasher.finalize())
}

fn encrypt_with_xwing_secret(ss: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key = hkdf_sha256_array::<32>(Some(aad), ss, XWING_AEAD_INFO)
        .expect("X-Wing AEAD HKDF must succeed");
    let cipher = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(key));
    cipher
        .encrypt(&ChaCha20Nonce::from_bytes([0u8; 12]), plaintext, aad)
        .expect("ChaCha20-Poly1305 encryption must succeed")
}

fn decrypt_with_xwing_secret(
    ss: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = hkdf_sha256_array::<32>(Some(aad), ss, XWING_AEAD_INFO)?;
    let cipher = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(key));
    cipher.decrypt(&ChaCha20Nonce::from_bytes([0u8; 12]), ciphertext, aad)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn x_wing_kem_round_trip_property(
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        aad in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let provider = XWingProvider::new();
        let (pk, sk) = provider.generate().expect("keygen must succeed");
        let sealed = provider
            .seal(&pk, &plaintext, &aad)
            .expect("seal must succeed");
        let opened = provider
            .open(&sk, &sealed, &aad)
            .expect("matching key and AAD must open");
        prop_assert_eq!(opened, plaintext);
    }
}

#[test]
fn x_wing_kem_component_combiner_matches_draft_kats() {
    for (i, v) in vectors().iter().enumerate() {
        let c = components_from_vector(v);
        let combined = x_wing_combiner(&c.ss_mlkem, &c.ss_x25519, &c.ct_x25519, &c.pk_x25519);
        assert_eq!(
            combined.as_slice(),
            v.ss.as_slice(),
            "vector #{i}: reconstructed component combiner must match draft KAT"
        );
    }
}

#[test]
fn x_wing_kem_hybrid_security_survives_either_component_zeroed() {
    let v = vectors().remove(0);
    let c = components_from_vector(&v);
    let plaintext = b"FCP V4 zone key under hybrid component compromise";
    let aad = b"kyopb.1.2.5:hybrid-security";
    let zero = [0u8; 32];

    let ss_both_live = x_wing_combiner(&c.ss_mlkem, &c.ss_x25519, &c.ct_x25519, &c.pk_x25519);
    assert_eq!(ss_both_live.as_slice(), v.ss.as_slice());

    let ss_without_mlkem = x_wing_combiner(&zero, &c.ss_x25519, &c.ct_x25519, &c.pk_x25519);
    let ct_without_mlkem = encrypt_with_xwing_secret(&ss_without_mlkem, plaintext, aad);
    assert_eq!(
        decrypt_with_xwing_secret(&ss_without_mlkem, &ct_without_mlkem, aad).unwrap(),
        plaintext
    );

    let ss_without_x25519 = x_wing_combiner(&c.ss_mlkem, &zero, &c.ct_x25519, &c.pk_x25519);
    let ct_without_x25519 = encrypt_with_xwing_secret(&ss_without_x25519, plaintext, aad);
    assert_eq!(
        decrypt_with_xwing_secret(&ss_without_x25519, &ct_without_x25519, aad).unwrap(),
        plaintext
    );

    let ss_both_zero = x_wing_combiner(&zero, &zero, &c.ct_x25519, &c.pk_x25519);
    let normal_ct = encrypt_with_xwing_secret(&ss_both_live, plaintext, aad);
    assert!(
        decrypt_with_xwing_secret(&ss_both_zero, &normal_ct, aad).is_err(),
        "zeroing both hybrid inputs must not authenticate a real sealed box"
    );

    assert_ne!(ss_without_mlkem, ss_both_zero);
    assert_ne!(ss_without_x25519, ss_both_zero);
}

#[test]
fn x_wing_kem_kat_secret_is_not_vanilla_x25519_baseline() {
    let v = vectors().remove(0);
    let c = components_from_vector(&v);
    let combined = x_wing_combiner(&c.ss_mlkem, &c.ss_x25519, &c.ct_x25519, &c.pk_x25519);

    assert_eq!(combined.as_slice(), v.ss.as_slice());
    assert_ne!(
        combined, c.ss_x25519,
        "X-Wing KAT shared secret must not collapse to the vanilla X25519 DH output"
    );
}
