#![no_main]

use fcp_crypto::cose::CoseToken;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::kid::KeyId;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(token) = CoseToken::from_cbor(data) else {
        return;
    };

    let reencoded = match token.to_cbor() {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    let Ok(round_tripped) = CoseToken::from_cbor(&reencoded) else {
        panic!("parsed token must re-parse after to_cbor");
    };
    let re_reencoded = round_tripped
        .to_cbor()
        .expect("re-parsed token must re-encode");
    assert_eq!(
        reencoded, re_reencoded,
        "COSE re-encoding must be byte-stable across parse roundtrips"
    );

    let fixed_key = Ed25519SigningKey::from_bytes(&[0x41; 32])
        .expect("static fuzz signing key must parse");
    let verify_pk = fixed_key.verifying_key();

    let _ = token.verify(&verify_pk);

    let mismatched_kid = KeyId::from_bytes([0xAB; 8]);
    let lookup_called = std::cell::Cell::new(false);
    let _ = token.verify_with_lookup(|kid| {
        lookup_called.set(true);
        if kid == &mismatched_kid {
            Some(verify_pk.clone())
        } else {
            None
        }
    });

    let _ = token.claims_unverified();
    let _ = token.get_key_id();
});
