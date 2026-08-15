//! Shared zeroizing secret storage and bounded credential framing.

#![forbid(unsafe_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod credential_frame;

pub use credential_frame::{CredentialFrameError, encode, parse, read, validate_secret};

/// Wrapper for secret bytes that zeroizes its owned buffer on drop.
///
/// Cloning is deliberate: every clone owns an independent buffer and each
/// buffer is zeroized when its wrapper is dropped.
///
/// Secret values intentionally do not serialize:
///
/// ```compile_fail
/// let secret = fcp_secret::ZeroizingSecret::from("do-not-serialize");
/// let _json = serde_json::to_string(&secret).unwrap();
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingSecret(Vec<u8>);

impl ZeroizingSecret {
    /// Construct a new zeroizing secret from owned bytes.
    ///
    /// The input is moved into this wrapper and will be zeroized when the
    /// wrapper is dropped.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Construct a new zeroizing secret from a UTF-8 string slice.
    ///
    /// This copies the string into an owned byte buffer. The caller still owns
    /// the original string and is responsible for its lifecycle.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(secret: &str) -> Self {
        Self(secret.as_bytes().to_vec())
    }

    /// Construct from an already-owned `Vec<u8>` with explicit zeroize-on-drop
    /// semantics.
    ///
    /// This is equivalent to [`Self::new`] for `Vec<u8>`, but the method name
    /// is useful at call sites where the security contract should be visible.
    #[must_use]
    pub const fn with_zeroize_drop(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Borrow the secret bytes inside a closure.
    ///
    /// Closure-scoped access prevents callers from storing references to the
    /// inner bytes beyond the borrow. The lifetime of the returned slice is
    /// tied to the closure's stack frame, not the wrapper's lifetime, so any
    /// attempt to escape the slice fails to compile.
    pub fn with_bytes<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }

    /// Mutably borrow the secret bytes inside a closure.
    ///
    /// This is intended for secret-bearing I/O scratch storage. Closure-scoped
    /// access prevents a mutable slice from escaping while the owned buffer
    /// remains zeroize-on-drop on every return path.
    pub fn with_bytes_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }

    /// Get the length of the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Compare two secrets in constant time for equal-length inputs.
    ///
    /// Length still affects the result before the constant-time byte
    /// comparison. This avoids implementing `PartialEq`/`Ord`, whose standard
    /// contracts do not promise timing behavior suitable for secret material.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && subtle::ConstantTimeEq::ct_eq(self.0.as_slice(), other.0.as_slice()).into()
    }

    /// Compare a secret against a borrowed byte slice in constant time for
    /// equal-length inputs. Returns `false` for unequal-length comparisons
    /// without leaking position information beyond the length difference.
    ///
    /// Use this when comparing against test fixtures or precomputed expected
    /// values without exposing the inner buffer.
    #[must_use]
    pub fn ct_eq_bytes(&self, other: &[u8]) -> bool {
        self.0.len() == other.len()
            && subtle::ConstantTimeEq::ct_eq(self.0.as_slice(), other).into()
    }
}

impl From<Vec<u8>> for ZeroizingSecret {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for ZeroizingSecret {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ZeroizingSecret {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl std::str::FromStr for ZeroizingSecret {
    type Err = std::convert::Infallible;

    fn from_str(secret: &str) -> Result<Self, Self::Err> {
        Ok(Self(secret.as_bytes().to_vec()))
    }
}

impl std::fmt::Debug for ZeroizingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingSecret(<redacted, len={}>)", self.0.len())
    }
}

impl std::fmt::Display for ZeroizingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingSecret(<redacted, len={}>)", self.0.len())
    }
}
