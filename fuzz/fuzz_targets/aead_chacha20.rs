#![no_main]

//! Fuzz target for ChaCha20-Poly1305 + XChaCha20-Poly1305 AEAD
//! primitives in `fcp_crypto::aead` (aead.rs:180-386).
//!
//! Existing fuzz targets exercise these only via the `ZoneKeyAlgorithm`
//! wrapper in raptorq / symbol envelopes. The cipher surface itself
//! (round-trip, AAD/nonce/key binding, free-function family,
//! prepended-nonce convenience layer, counter-nonce layout) is NOT
//! directly fuzzed.
//!
//! A regression that:
//!   - swapped key into nonce input would silently let identical
//!     plaintexts authenticate under different (k, n) pairs.
//!   - dropped AAD from the cipher input would let an attacker
//!     re-authenticate the same ciphertext under a different
//!     associated-data context.
//!   - made `decrypt_with_prepended_nonce` accept a too-short input
//!     would dereference past the end of the nonce slice.
//!   - changed the byte layout of `ChaCha20Nonce::from_counter` would
//!     defeat deterministic-nonce protocols built on top of it.
//!
//! Properties asserted:
//!
//!   1. **CC20-P1305 round-trip**: encrypt(k, n, pt, aad) → decrypt
//!      MUST return pt verbatim.
//!   2. **XCC20-P1305 round-trip**.
//!   3. **AAD binding**: decrypt with mutated AAD returns
//!      `AeadDecryptFailed`.
//!   4. **Nonce binding**: decrypt with mutated nonce fails.
//!   5. **Key binding**: decrypt with mutated key fails.
//!   6. **Ciphertext mutation**: a 1-byte mutation in ciphertext
//!      MUST cause decrypt to fail.
//!   7. **Free function == method**: `chacha20_encrypt ==
//!      ChaCha20Poly1305Cipher::encrypt`, same for `_decrypt` and
//!      both `xchacha20_*` variants.
//!   8. **Random-nonce + prepended-nonce round-trip**:
//!      `decrypt_with_prepended_nonce(encrypt_with_random_nonce(pt,
//!      aad), aad) == pt`.
//!   9. **Truncated prepended-nonce rejection**: any input shorter
//!      than `XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE` (24 + 16 = 40)
//!      MUST yield `AeadDecryptFailed` from
//!      `decrypt_with_prepended_nonce`.
//!  10. **`ChaCha20Nonce::from_counter` layout**: counter is placed
//!      at bytes [4..12] little-endian; bytes [0..4] are zero.
//!  11. **`ChaCha20Nonce::from_counter_directional` layout**:
//!      direction is byte 0; counter at [4..12] LE; bytes [1..4] zero.
//!
//!   Once-gated anchors verify each layout, the truncation cap, and
//!   round-trip on a known fixed (k, n, pt, aad).

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::aead::{
    AEAD_KEY_SIZE, AEAD_TAG_SIZE, AeadKey, CHACHA20_NONCE_SIZE, ChaCha20Nonce,
    ChaCha20Poly1305Cipher, XCHACHA20_NONCE_SIZE, XChaCha20Nonce, XChaCha20Poly1305Cipher,
    chacha20_decrypt, chacha20_encrypt, xchacha20_decrypt, xchacha20_encrypt,
};
use fcp_crypto::{CryptoError, CryptoResult};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static AEAD_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    key_bytes: [u8; AEAD_KEY_SIZE],
    nonce_bytes: [u8; CHACHA20_NONCE_SIZE],
    xnonce_bytes: [u8; XCHACHA20_NONCE_SIZE],
    plaintext: Vec<u8>,
    aad: Vec<u8>,
    /// Byte to flip in ciphertext for Property 6 (mod len).
    flip_byte: u16,
    /// Byte to flip in AAD for Property 3 (mod len).
    aad_flip: u16,
    /// Byte to flip in nonce for Property 4 (mod 12).
    nonce_flip: u8,
    /// Byte to flip in key for Property 5 (mod 32).
    key_flip: u8,
    /// Counter for layout test.
    counter: u64,
    /// Direction byte for directional-layout test.
    direction: u8,
}

const MAX_PT: usize = 4096;
const MAX_AAD: usize = 1024;

fuzz_target!(|data: &[u8]| {
    AEAD_ANCHOR.call_once(assert_aead_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.plaintext.len() > MAX_PT || input.aad.len() > MAX_AAD {
        return;
    }

    let key = AeadKey::from_bytes(input.key_bytes);
    let nonce = ChaCha20Nonce::from_bytes(input.nonce_bytes);
    let xnonce = XChaCha20Nonce::from_bytes(input.xnonce_bytes);

    let cc20 = ChaCha20Poly1305Cipher::new(&key);
    let xcc20 = XChaCha20Poly1305Cipher::new(&key);

    // ── PROPERTY 1: CC20-P1305 round-trip ───────────────────────────────
    let ct = cc20
        .encrypt(&nonce, &input.plaintext, &input.aad)
        .expect("CC20 encrypt");
    let pt = cc20.decrypt(&nonce, &ct, &input.aad).expect("CC20 decrypt");
    assert_eq!(
        pt, input.plaintext,
        "ChaCha20-Poly1305 round-trip lost plaintext"
    );

    // ── PROPERTY 2: XCC20-P1305 round-trip ──────────────────────────────
    let xct = xcc20
        .encrypt(&xnonce, &input.plaintext, &input.aad)
        .expect("XCC20 encrypt");
    let xpt = xcc20
        .decrypt(&xnonce, &xct, &input.aad)
        .expect("XCC20 decrypt");
    assert_eq!(
        xpt, input.plaintext,
        "XChaCha20-Poly1305 round-trip lost plaintext"
    );

    // ── PROPERTY 7: free function == method ─────────────────────────────
    let ct_free = chacha20_encrypt(&key, &nonce, &input.plaintext, &input.aad)
        .expect("chacha20_encrypt free");
    assert_eq!(
        ct_free, ct,
        "chacha20_encrypt diverged from ChaCha20Poly1305Cipher::encrypt"
    );
    let pt_free = chacha20_decrypt(&key, &nonce, &ct, &input.aad).expect("chacha20_decrypt free");
    assert_eq!(
        pt_free, input.plaintext,
        "chacha20_decrypt diverged from method"
    );
    let xct_free = xchacha20_encrypt(&key, &xnonce, &input.plaintext, &input.aad)
        .expect("xchacha20_encrypt free");
    assert_eq!(
        xct_free, xct,
        "xchacha20_encrypt diverged from XChaCha20Poly1305Cipher::encrypt"
    );
    let xpt_free =
        xchacha20_decrypt(&key, &xnonce, &xct, &input.aad).expect("xchacha20_decrypt free");
    assert_eq!(
        xpt_free, input.plaintext,
        "xchacha20_decrypt diverged from method"
    );

    // ── PROPERTY 3: AAD binding ─────────────────────────────────────────
    if !input.aad.is_empty() {
        let mut bad_aad = input.aad.clone();
        let idx = (input.aad_flip as usize) % bad_aad.len();
        bad_aad[idx] ^= 0x01;
        match cc20.decrypt(&nonce, &ct, &bad_aad) {
            Err(CryptoError::AeadDecryptFailed) => {}
            other => panic!(
                "CC20 decrypt with mutated AAD returned {other:?}; expected AeadDecryptFailed"
            ),
        }
    } else {
        // Empty AAD path: decrypting with non-empty AAD must fail.
        let alt_aad = b"x";
        match cc20.decrypt(&nonce, &ct, alt_aad) {
            Err(CryptoError::AeadDecryptFailed) => {}
            other => {
                panic!("CC20 decrypt with non-empty AAD vs empty-AAD ciphertext returned {other:?}")
            }
        }
    }

    // ── PROPERTY 4: nonce binding ───────────────────────────────────────
    let mut bad_nonce_bytes = input.nonce_bytes;
    let idx = (input.nonce_flip as usize) % CHACHA20_NONCE_SIZE;
    bad_nonce_bytes[idx] ^= 0x01;
    let bad_nonce = ChaCha20Nonce::from_bytes(bad_nonce_bytes);
    if bad_nonce_bytes != input.nonce_bytes {
        match cc20.decrypt(&bad_nonce, &ct, &input.aad) {
            Err(CryptoError::AeadDecryptFailed) => {}
            other => panic!("CC20 decrypt with mutated nonce returned {other:?}"),
        }
    }

    // ── PROPERTY 5: key binding ─────────────────────────────────────────
    let mut bad_key_bytes = input.key_bytes;
    let idx = (input.key_flip as usize) % AEAD_KEY_SIZE;
    bad_key_bytes[idx] ^= 0x01;
    let bad_key = AeadKey::from_bytes(bad_key_bytes);
    let bad_cc20 = ChaCha20Poly1305Cipher::new(&bad_key);
    match bad_cc20.decrypt(&nonce, &ct, &input.aad) {
        Err(CryptoError::AeadDecryptFailed) => {}
        other => panic!("CC20 decrypt with mutated key returned {other:?}"),
    }

    // ── PROPERTY 6: ciphertext mutation ────────────────────────────────
    if !ct.is_empty() {
        let mut bad_ct = ct.clone();
        let idx = (input.flip_byte as usize) % bad_ct.len();
        bad_ct[idx] ^= 0x01;
        match cc20.decrypt(&nonce, &bad_ct, &input.aad) {
            Err(CryptoError::AeadDecryptFailed) => {}
            other => panic!("CC20 decrypt with mutated ciphertext returned {other:?}"),
        }
    }

    // ── PROPERTY 8: random-nonce / prepended-nonce round-trip ──────────
    let env = xcc20
        .encrypt_with_random_nonce(&input.plaintext, &input.aad)
        .expect("encrypt_with_random_nonce");
    assert!(
        env.len() >= XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE,
        "random-nonce envelope shorter than nonce+tag"
    );
    let pt_env = xcc20
        .decrypt_with_prepended_nonce(&env, &input.aad)
        .expect("decrypt_with_prepended_nonce");
    assert_eq!(
        pt_env, input.plaintext,
        "random-nonce + prepended-nonce round-trip lost plaintext"
    );

    // ── PROPERTY 9: truncated prepended-nonce rejection ────────────────
    let cap = XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE;
    let truncated = if env.len() > cap {
        // Use a deliberately short prefix.
        env[..cap.saturating_sub(1)].to_vec()
    } else {
        // env itself isn't long enough; treat as short.
        env[..env.len().saturating_sub(1)].to_vec()
    };
    if truncated.len() < cap {
        match xcc20.decrypt_with_prepended_nonce(&truncated, &input.aad) {
            Err(CryptoError::AeadDecryptFailed) => {}
            other => panic!(
                "decrypt_with_prepended_nonce on len={} (< {}) returned {other:?}; expected AeadDecryptFailed",
                truncated.len(),
                cap
            ),
        }
    }

    // ── PROPERTY 10: ChaCha20Nonce::from_counter layout ────────────────
    let counter_nonce = ChaCha20Nonce::from_counter(input.counter);
    let bytes = counter_nonce.as_bytes();
    assert_eq!(&bytes[0..4], &[0u8; 4], "from_counter bytes 0..4 not zero");
    assert_eq!(
        &bytes[4..12],
        &input.counter.to_le_bytes(),
        "from_counter counter not at bytes 4..12 LE"
    );

    // ── PROPERTY 11: ChaCha20Nonce::from_counter_directional layout ────
    let dir_nonce = ChaCha20Nonce::from_counter_directional(input.counter, input.direction);
    let bytes = dir_nonce.as_bytes();
    assert_eq!(bytes[0], input.direction, "directional byte 0 != direction");
    assert_eq!(&bytes[1..4], &[0u8; 3], "directional bytes 1..4 not zero");
    assert_eq!(
        &bytes[4..12],
        &input.counter.to_le_bytes(),
        "directional counter not at bytes 4..12 LE"
    );

    // ── try_from_slice length gates ─────────────────────────────────────
    let aead_short: CryptoResult<AeadKey> = AeadKey::try_from_slice(&input.nonce_bytes);
    assert!(
        matches!(
            aead_short,
            Err(CryptoError::InvalidKeyLength {
                expected: AEAD_KEY_SIZE,
                ..
            })
        ),
        "AeadKey::try_from_slice accepted 12-byte input"
    );
    let nonce_short: CryptoResult<ChaCha20Nonce> = ChaCha20Nonce::try_from_slice(&input.key_bytes);
    assert!(
        matches!(
            nonce_short,
            Err(CryptoError::InvalidNonceLength {
                expected: CHACHA20_NONCE_SIZE,
                ..
            })
        ),
        "ChaCha20Nonce::try_from_slice accepted 32-byte input"
    );
});

/// Once-gated anchors: known-good round-trip, layout, truncation cap.
fn assert_aead_anchored() {
    let key = AeadKey::from_bytes([0x42u8; AEAD_KEY_SIZE]);
    let nonce = ChaCha20Nonce::from_counter(7);
    let pt = b"FCP2 anchor plaintext";
    let aad = b"FCP2 anchor AAD";

    let cc20 = ChaCha20Poly1305Cipher::new(&key);
    let ct = cc20.encrypt(&nonce, pt, aad).expect("ANCHOR: CC20 encrypt");
    let dec = cc20
        .decrypt(&nonce, &ct, aad)
        .expect("ANCHOR: CC20 decrypt");
    assert_eq!(
        dec.as_slice(),
        pt.as_slice(),
        "ANCHOR REGRESSION: CC20 round-trip lost plaintext"
    );

    // Free-function agreement on a known input.
    let ct_free = chacha20_encrypt(&key, &nonce, pt, aad).expect("ANCHOR: free encrypt");
    assert_eq!(ct_free, ct, "ANCHOR: chacha20_encrypt diverged");

    // Counter layout: from_counter(7) bytes 4..12 == 7u64.to_le_bytes().
    let n = ChaCha20Nonce::from_counter(7);
    let nb = n.as_bytes();
    assert_eq!(
        &nb[0..4],
        &[0u8; 4],
        "ANCHOR: from_counter prefix bytes != 0"
    );
    assert_eq!(
        &nb[4..12],
        &7u64.to_le_bytes(),
        "ANCHOR REGRESSION: from_counter counter not at bytes 4..12 LE"
    );

    // Directional layout.
    let dn = ChaCha20Nonce::from_counter_directional(0x1234_5678_9ABC_DEF0, 0xAB);
    let dnb = dn.as_bytes();
    assert_eq!(dnb[0], 0xAB, "ANCHOR: directional byte 0 != direction");
    assert_eq!(&dnb[1..4], &[0u8; 3], "ANCHOR: directional bytes 1..4 != 0");
    assert_eq!(
        &dnb[4..12],
        &0x1234_5678_9ABC_DEF0u64.to_le_bytes(),
        "ANCHOR: directional counter not LE"
    );

    // Truncated prepended-nonce: 39 bytes (< 40 = 24+16) must reject.
    let xkey = AeadKey::from_bytes([0x55u8; AEAD_KEY_SIZE]);
    let xcc20 = XChaCha20Poly1305Cipher::new(&xkey);
    let too_short = vec![0u8; XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE - 1];
    match xcc20.decrypt_with_prepended_nonce(&too_short, b"") {
        Err(CryptoError::AeadDecryptFailed) => {}
        other => panic!(
            "ANCHOR REGRESSION: decrypt_with_prepended_nonce on 39-byte input returned {other:?}"
        ),
    }

    // Length-gate boundaries.
    match AeadKey::try_from_slice(&[0u8; 31]) {
        Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 31,
        }) => {}
        other => panic!("ANCHOR: AeadKey 31-byte expected InvalidKeyLength, got {other:?}"),
    }
    match ChaCha20Nonce::try_from_slice(&[0u8; 11]) {
        Err(CryptoError::InvalidNonceLength {
            expected: 12,
            actual: 11,
        }) => {}
        other => panic!("ANCHOR: ChaCha20Nonce 11-byte expected InvalidNonceLength, got {other:?}"),
    }
    match XChaCha20Nonce::try_from_slice(&[0u8; 23]) {
        Err(CryptoError::InvalidNonceLength {
            expected: 24,
            actual: 23,
        }) => {}
        other => {
            panic!("ANCHOR: XChaCha20Nonce 23-byte expected InvalidNonceLength, got {other:?}")
        }
    }
}
