//! ChaCha20-Poly1305 golden-vector fixtures.

use super::chacha20_poly1305::{CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE};

/// Static ChaCha20-Poly1305 test vector.
#[derive(Debug, Clone)]
pub struct Chacha20Poly1305Vector {
    /// Human-readable vector name.
    pub name: &'static str,
    /// 32-byte AEAD key.
    pub key: [u8; CHACHA20POLY1305_KEY_SIZE],
    /// 12-byte AEAD nonce.
    pub nonce: [u8; CHACHA20POLY1305_NONCE_SIZE],
    /// Plaintext.
    pub plaintext: Vec<u8>,
    /// Associated authenticated data.
    pub aad: Vec<u8>,
    /// Expected ciphertext with appended tag, when the vector has fixed bytes.
    pub expected_ciphertext: Option<Vec<u8>>,
}

/// Return the canonical RFC 8439 vector plus deterministic fixed fixtures.
#[must_use]
pub fn vectors() -> Vec<Chacha20Poly1305Vector> {
    let mut vectors = vec![rfc8439_vector()];
    let lengths = [
        0_usize, 1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 255,
        256, 257, 511, 512, 513, 1023, 1024, 2048, 4096, 8192,
    ];
    for (idx, len) in lengths.into_iter().enumerate() {
        vectors.push(generated_vector(idx, len));
    }
    vectors
}

const RFC8439_AAD: &[u8] = &[
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];

const RFC8439_PLAINTEXT: &[u8] =
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

const RFC8439_CIPHERTEXT: &[u8] = &[
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
    0x06, 0x91,
];

fn rfc8439_vector() -> Chacha20Poly1305Vector {
    Chacha20Poly1305Vector {
        name: "rfc8439-aead",
        key: [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ],
        nonce: [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ],
        plaintext: RFC8439_PLAINTEXT.to_vec(),
        aad: RFC8439_AAD.to_vec(),
        expected_ciphertext: Some(RFC8439_CIPHERTEXT.to_vec()),
    }
}

fn generated_vector(idx: usize, plaintext_len: usize) -> Chacha20Poly1305Vector {
    let seed = u64::try_from(idx).unwrap_or(0).wrapping_mul(0x9e37_79b9);
    let key_vec = deterministic_bytes(seed ^ 0xaead, CHACHA20POLY1305_KEY_SIZE);
    let nonce_vec = deterministic_bytes(seed ^ 0xfeed, CHACHA20POLY1305_NONCE_SIZE);
    let aad = deterministic_bytes(seed ^ 0xcafe, (idx % 19) + 1);
    let plaintext = deterministic_bytes(seed ^ 0xbeef, plaintext_len);
    let mut key = [0_u8; CHACHA20POLY1305_KEY_SIZE];
    let mut nonce = [0_u8; CHACHA20POLY1305_NONCE_SIZE];
    key.copy_from_slice(&key_vec);
    nonce.copy_from_slice(&nonce_vec);
    Chacha20Poly1305Vector {
        name: "generated-deterministic",
        key,
        nonce,
        plaintext,
        aad,
        expected_ciphertext: None,
    }
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0xd1b5_4a32_d192_ed03;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state = state.wrapping_mul(0x94d0_49bb_1331_11eb);
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}
