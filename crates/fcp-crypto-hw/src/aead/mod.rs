//! AEAD hardware-dispatch surfaces.

pub mod chacha20_poly1305;
pub mod golden_vectors;

pub use chacha20_poly1305::{
    CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE, CHACHA20POLY1305_TAG_SIZE,
    Chacha20Poly1305Backend, Chacha20Poly1305Dispatch, Chacha20Poly1305Error, open_avx2,
    open_scalar, open_sse3, seal_avx2, seal_scalar, seal_sse3,
};
