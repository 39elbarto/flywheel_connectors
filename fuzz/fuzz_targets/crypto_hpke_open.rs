#![no_main]

//! Attacker-controlled HPKE sealed-box parse + open.
//!
//! Covers:
//! * `HpkeSealedBox::from_bytes` on adversarial wire bytes (may be truncated,
//!   over-sized, or contain arbitrary `enc` prefixes claiming to be a valid
//!   X25519 encapsulated public key).
//! * `to_bytes` round-trip stability on every parsed value.
//! * `hpke_open` against a fixed recipient secret key, with attacker-chosen
//!   Fcp2Aad fields. Decryption MUST return `Err`, never panic, no matter
//!   what adversary bytes were supplied. A successful decrypt on random
//!   bytes would be a catastrophic signal (tag forgery) and we assert it
//!   did not happen for input that did not originate from us.

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use fcp_crypto::hpke_seal::{Fcp2Aad, HpkeSealedBox, hpke_open};
use fcp_crypto::x25519::X25519SecretKey;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_AAD_FIELD_BYTES: usize = 64;

#[derive(Debug)]
struct AttackerAad {
    zone_id: Vec<u8>,
    recipient_node_id: Vec<u8>,
    purpose_tag: u8,
    issued_at: u64,
}

impl<'a> Arbitrary<'a> for AttackerAad {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let zone_len = u.int_in_range(0..=MAX_AAD_FIELD_BYTES)?;
        let zone_id = u.bytes(zone_len)?.to_vec();
        let node_len = u.int_in_range(0..=MAX_AAD_FIELD_BYTES)?;
        let recipient_node_id = u.bytes(node_len)?.to_vec();
        Ok(Self {
            zone_id,
            recipient_node_id,
            purpose_tag: u.arbitrary()?,
            issued_at: u.arbitrary()?,
        })
    }
}

#[derive(Debug, Arbitrary)]
struct Input<'a> {
    /// Raw bytes fed to `HpkeSealedBox::from_bytes`.
    sealed_bytes: &'a [u8],
    /// Attacker-chosen AAD (open with wrong AAD must Err, not panic).
    aad: AttackerAad,
}

fuzz_target!(|input: Input| {
    if input.sealed_bytes.len() > MAX_INPUT_BYTES {
        return;
    }

    // Layer 1: deserialize adversarial bytes.
    let Ok(sealed) = HpkeSealedBox::from_bytes(input.sealed_bytes) else {
        return;
    };

    // Layer 2: serialization round-trip must be byte-stable after a parse.
    let reencoded = sealed.to_bytes();
    let reparsed = HpkeSealedBox::from_bytes(&reencoded)
        .expect("parsed sealed box must re-parse from to_bytes output");
    assert_eq!(
        reencoded,
        reparsed.to_bytes(),
        "HpkeSealedBox to_bytes must be idempotent after parse"
    );

    // Layer 3: hpke_open against a deterministic recipient key.
    // The attacker never had our secret; decryption must fail with Err,
    // never panic, and never succeed.
    let sk = X25519SecretKey::from_bytes([0x5A; 32]);
    let aad = match input.aad.purpose_tag % 3 {
        0 => Fcp2Aad::for_zone_key(
            &input.aad.zone_id,
            &input.aad.recipient_node_id,
            input.aad.issued_at,
        ),
        1 => Fcp2Aad::for_objectid_key(
            &input.aad.zone_id,
            &input.aad.recipient_node_id,
            input.aad.issued_at,
        ),
        _ => Fcp2Aad::for_secret_share(
            &input.aad.zone_id,
            &input.aad.recipient_node_id,
            input.aad.issued_at,
        ),
    };

    let result = hpke_open(&sk, &sealed, &aad);
    assert!(
        result.is_err(),
        "hpke_open on adversary-supplied sealed box must not decrypt to Ok \
         (would indicate Poly1305 tag forgery)"
    );
});
