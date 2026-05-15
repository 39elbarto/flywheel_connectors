//! ChaCha20-Poly1305 dispatch helpers.
//!
//! `RustCrypto` owns the low-level `ChaCha20` block-function dispatch. This module
//! gives FCP a stable backend-selection surface, failure taxonomy, and parity
//! test hooks without introducing unsafe code or changing the existing
//! `fcp-crypto` AEAD API.

use std::{env, error::Error, fmt};

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};

use crate::cpuid::HwFeatureSet;

/// ChaCha20-Poly1305 key size in bytes.
pub const CHACHA20POLY1305_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size in bytes.
pub const CHACHA20POLY1305_NONCE_SIZE: usize = 12;
/// Poly1305 tag size in bytes.
pub const CHACHA20POLY1305_TAG_SIZE: usize = 16;

/// FCP-facing ChaCha20-Poly1305 backend labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chacha20Poly1305Backend {
    /// Portable scalar fallback.
    Scalar,
    /// x86 SSE3-capable backend label.
    X86Sse3,
    /// x86 AVX2-capable backend label.
    X86Avx2,
}

impl Chacha20Poly1305Backend {
    /// Stable string form for logs, docs, and JSON evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::X86Sse3 => "x86_sse3",
            Self::X86Avx2 => "x86_avx2",
        }
    }

    /// Parse an operator-facing backend label.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::UnknownBackend`] when `value` is not a
    /// supported backend label.
    pub fn parse(value: &str) -> Result<Self, Chacha20Poly1305Error> {
        match value {
            "scalar" | "portable" => Ok(Self::Scalar),
            "x86_sse3" | "sse3" => Ok(Self::X86Sse3),
            "x86_avx2" | "avx2" => Ok(Self::X86Avx2),
            other => Err(Chacha20Poly1305Error::UnknownBackend {
                value: other.to_owned(),
            }),
        }
    }
}

/// ChaCha20-Poly1305 dispatch and AEAD errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chacha20Poly1305Error {
    /// The requested backend label is unknown.
    UnknownBackend {
        /// Raw operator-provided backend name.
        value: String,
    },
    /// `FCP_CRYPTO_BACKEND` was present but not valid Unicode.
    InvalidOverrideUnicode,
    /// Encryption failed.
    EncryptFailed,
    /// Authentication failed while opening ciphertext.
    TagMismatch,
}

impl fmt::Display for Chacha20Poly1305Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBackend { value } => {
                write!(f, "unknown ChaCha20-Poly1305 backend override: {value}")
            }
            Self::InvalidOverrideUnicode => f.write_str("FCP_CRYPTO_BACKEND is not valid Unicode"),
            Self::EncryptFailed => f.write_str("ChaCha20-Poly1305 encryption failed"),
            Self::TagMismatch => f.write_str("ChaCha20-Poly1305 authentication tag mismatch"),
        }
    }
}

impl Error for Chacha20Poly1305Error {}

/// ChaCha20-Poly1305 dispatcher with an explicit selected backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chacha20Poly1305Dispatch {
    backend: Chacha20Poly1305Backend,
}

impl Chacha20Poly1305Dispatch {
    /// Build a dispatcher from detected hardware features.
    #[must_use]
    pub const fn from_features(features: HwFeatureSet) -> Self {
        Self {
            backend: select_chacha20_backend(features),
        }
    }

    /// Build a dispatcher from detected features and an optional override.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::UnknownBackend`] when `override_value`
    /// contains an unsupported backend label.
    pub fn from_features_with_override(
        features: HwFeatureSet,
        override_value: Option<&str>,
    ) -> Result<Self, Chacha20Poly1305Error> {
        let backend = match override_value {
            Some(value) if !value.trim().is_empty() => {
                Chacha20Poly1305Backend::parse(value.trim())?
            }
            _ => select_chacha20_backend(features),
        };
        Ok(Self { backend })
    }

    /// Build a dispatcher from detected features and `FCP_CRYPTO_BACKEND`.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::UnknownBackend`] when the environment
    /// value names an unsupported backend. Returns
    /// [`Chacha20Poly1305Error::InvalidOverrideUnicode`] when the environment
    /// variable is present but not valid Unicode.
    pub fn from_env(features: HwFeatureSet) -> Result<Self, Chacha20Poly1305Error> {
        match env::var("FCP_CRYPTO_BACKEND") {
            Ok(value) => Self::from_features_with_override(features, Some(&value)),
            Err(env::VarError::NotPresent) => Ok(Self::from_features(features)),
            Err(env::VarError::NotUnicode(_)) => Err(Chacha20Poly1305Error::InvalidOverrideUnicode),
        }
    }

    /// Build a dispatcher for an explicit backend.
    #[must_use]
    pub const fn with_backend(backend: Chacha20Poly1305Backend) -> Self {
        Self { backend }
    }

    /// Return the selected backend label.
    #[must_use]
    pub const fn backend(self) -> Chacha20Poly1305Backend {
        self.backend
    }

    /// Seal plaintext with associated data, returning ciphertext with tag.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::EncryptFailed`] if the AEAD layer
    /// rejects otherwise well-shaped inputs.
    pub fn seal(
        self,
        key: &[u8; CHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Chacha20Poly1305Error> {
        match self.backend {
            Chacha20Poly1305Backend::Scalar => seal_scalar(key, nonce, plaintext, aad),
            Chacha20Poly1305Backend::X86Sse3 => seal_sse3(key, nonce, plaintext, aad),
            Chacha20Poly1305Backend::X86Avx2 => seal_avx2(key, nonce, plaintext, aad),
        }
    }

    /// Open ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
    pub fn open(
        self,
        key: &[u8; CHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Chacha20Poly1305Error> {
        match self.backend {
            Chacha20Poly1305Backend::Scalar => open_scalar(key, nonce, ciphertext, aad),
            Chacha20Poly1305Backend::X86Sse3 => open_sse3(key, nonce, ciphertext, aad),
            Chacha20Poly1305Backend::X86Avx2 => open_avx2(key, nonce, ciphertext, aad),
        }
    }

    /// Return every backend safe to exercise for a feature set.
    #[must_use]
    pub fn available_backends(features: HwFeatureSet) -> Vec<Chacha20Poly1305Backend> {
        let mut backends = vec![Chacha20Poly1305Backend::Scalar];
        if features.has_sse3 {
            backends.push(Chacha20Poly1305Backend::X86Sse3);
        }
        if features.has_avx2 {
            backends.push(Chacha20Poly1305Backend::X86Avx2);
        }
        backends
    }
}

/// Seal through the scalar backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::EncryptFailed`] if encryption fails.
pub fn seal_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    seal_with_rustcrypto(key, nonce, plaintext, aad)
}

/// Open through the scalar backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
pub fn open_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    open_with_rustcrypto(key, nonce, ciphertext, aad)
}

/// Seal through the SSE3 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::EncryptFailed`] if encryption fails.
pub fn seal_sse3(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    seal_with_rustcrypto(key, nonce, plaintext, aad)
}

/// Open through the SSE3 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
pub fn open_sse3(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    open_with_rustcrypto(key, nonce, ciphertext, aad)
}

/// Seal through the AVX2 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::EncryptFailed`] if encryption fails.
pub fn seal_avx2(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    seal_with_rustcrypto(key, nonce, plaintext, aad)
}

/// Open through the AVX2 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
pub fn open_avx2(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    open_with_rustcrypto(key, nonce, ciphertext, aad)
}

const fn select_chacha20_backend(features: HwFeatureSet) -> Chacha20Poly1305Backend {
    if features.has_avx2 {
        Chacha20Poly1305Backend::X86Avx2
    } else if features.has_sse3 {
        Chacha20Poly1305Backend::X86Sse3
    } else {
        Chacha20Poly1305Backend::Scalar
    }
}

fn seal_with_rustcrypto(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Chacha20Poly1305Error::EncryptFailed)
}

fn open_with_rustcrypto(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Chacha20Poly1305Error::TagMismatch)
}
