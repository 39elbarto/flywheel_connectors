//! Shamir's Secret Sharing over GF(2^8) (NORMATIVE).
//!
//! This module implements k-of-n threshold secret sharing using Shamir's scheme
//! over the Galois field GF(2^8). This is the same field used by AES, ensuring
//! well-understood security properties.
//!
//! **Security properties:**
//! - Information-theoretic security: k-1 shares reveal nothing about the secret
//! - Constant-time operations to prevent timing side channels
//! - All secret material is zeroized on drop
//!
//! **Why GF(2^8)?**
//! - No carries/borrows → constant-time addition (XOR)
//! - 256 possible x-coordinates fits in a byte
//! - Same field as AES → battle-tested implementations
//!
//! # Example
//!
//! ```rust
//! use fcp_crypto::shamir::{split_secret, reconstruct_secret, ShamirShare};
//!
//! // Split a secret into 5 shares, requiring 3 to reconstruct
//! let secret = b"my secret key";
//! let shares = split_secret(secret, 3, 5).unwrap();
//!
//! // Any 3 shares can reconstruct the secret
//! let subset: Vec<ShamirShare> = shares.into_iter().take(3).collect();
//! let reconstructed = reconstruct_secret(&subset).unwrap();
//!
//! assert_eq!(&reconstructed[..], secret);
//! ```

use rand::{CryptoRng, Rng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during secret sharing operations.
#[derive(Debug, Error)]
pub enum ShamirError {
    /// Threshold k must be at least 1.
    #[error("threshold must be at least 1")]
    ThresholdTooSmall,

    /// Threshold k cannot exceed total shares n.
    #[error("threshold ({threshold}) cannot exceed total shares ({total})")]
    ThresholdExceedsTotal {
        /// The requested threshold.
        threshold: u8,
        /// The total number of shares.
        total: u8,
    },

    /// Total shares cannot exceed 255 (GF(2^8) constraint).
    #[error("total shares cannot exceed 255")]
    TooManyShares,

    /// Secret is empty.
    #[error("secret cannot be empty")]
    EmptySecret,

    /// Duplicate share indices detected.
    #[error("duplicate share index: {0}")]
    DuplicateIndex(u8),

    /// Share index 0 is reserved (corresponds to the secret).
    #[error("share index 0 is reserved")]
    ReservedIndex,

    /// Share lengths do not match.
    #[error("share lengths must match")]
    MismatchedLengths,

    /// HPKE sealing/opening failed.
    #[error("HPKE operation failed: {0}")]
    SealingFailed(String),
}

/// Result type for Shamir operations.
pub type ShamirResult<T> = Result<T, ShamirError>;

/// A single share from Shamir's secret sharing scheme.
///
/// Each share contains:
/// - `index`: The x-coordinate (1-255) for polynomial evaluation
/// - `data`: The y-values for each byte of the secret
///
/// The share reveals nothing about the secret without k-1 other shares.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    /// Share index (x-coordinate), 1-255.
    #[zeroize(skip)]
    index: u8,

    /// Share data (y-values).
    data: Vec<u8>,
}

impl ShamirShare {
    /// Create a new share with the given index and data.
    ///
    /// # Panics
    /// Panics if index is 0 (reserved for the secret itself).
    #[must_use]
    pub fn new(index: u8, data: Vec<u8>) -> Self {
        assert!(index != 0, "share index 0 is reserved");
        Self { index, data }
    }

    /// Get the share index (x-coordinate).
    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Get the share data (y-values).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the share data.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the share data is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Serialize the share to bytes: [index, data...].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.data.len());
        bytes.push(self.index);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize a share from bytes.
    ///
    /// # Errors
    /// Returns error if bytes is empty or index is 0.
    pub fn from_bytes(bytes: &[u8]) -> ShamirResult<Self> {
        if bytes.len() <= 1 {
            return Err(ShamirError::EmptySecret);
        }
        let index = bytes[0];
        if index == 0 {
            return Err(ShamirError::ReservedIndex);
        }
        Ok(Self {
            index,
            data: bytes[1..].to_vec(),
        })
    }
}

impl std::fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose share data in debug output
        f.debug_struct("ShamirShare")
            .field("index", &self.index)
            .field("len", &self.data.len())
            .field("data", &"[redacted]")
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GF(2^8) Arithmetic
// ─────────────────────────────────────────────────────────────────────────────

/// GF(2^8) element with constant-time operations.
///
/// Uses the AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B).
#[derive(Clone, Copy, Default, Zeroize)]
struct Gf256(u8);

impl Gf256 {
    /// The AES irreducible polynomial (without the x^8 term).
    const MODULUS: u16 = 0x11B;

    /// Create a new GF(2^8) element.
    #[inline]
    const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Get the inner value.
    #[inline]
    const fn value(self) -> u8 {
        self.0
    }

    /// Addition in GF(2^8) is XOR.
    #[inline]
    const fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    /// Subtraction in GF(2^8) is the same as addition (XOR).
    #[inline]
    const fn sub(self, other: Self) -> Self {
        self.add(other)
    }

    /// Multiplication in GF(2^8) using Russian peasant algorithm.
    /// Constant-time implementation.
    #[inline]
    fn mul(self, other: Self) -> Self {
        let mut a = u16::from(self.0);
        let mut b = u16::from(other.0);
        let mut result: u16 = 0;

        // Process all 8 bits (constant-time)
        for _ in 0..8 {
            // If low bit of b is set, XOR a into result
            let mask = 0u16.wrapping_sub(b & 1);
            result ^= a & mask;

            // Check if high bit of a is set (will overflow)
            let high_bit = (a >> 7) & 1;
            let reduce_mask = 0u16.wrapping_sub(high_bit);

            // Shift a left and conditionally reduce
            a = (a << 1) ^ (Self::MODULUS & reduce_mask);

            // Shift b right
            b >>= 1;
        }

        #[allow(clippy::cast_possible_truncation)]
        Self(result as u8)
    }

    /// Compute multiplicative inverse using extended Euclidean algorithm.
    /// Returns 0 for input 0 (not a valid field element for division).
    /// Constant-time implementation using Fermat's little theorem: a^254 = a^(-1) in GF(2^8).
    #[inline]
    fn inv(self) -> Self {
        // a^(-1) = a^254 in GF(2^8) by Fermat's little theorem
        // 254 = 0b11111110
        // We compute a^2, a^4, a^8, ..., a^128 and multiply selected powers

        let a2 = self.mul(self);
        let a4 = a2.mul(a2);
        let a8 = a4.mul(a4);
        let a16 = a8.mul(a8);
        let a32 = a16.mul(a16);
        let a64 = a32.mul(a32);
        let a128 = a64.mul(a64);

        // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
        // a^254 = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
        a128.mul(a64).mul(a32).mul(a16).mul(a8).mul(a4).mul(a2)
    }

    /// Division: a / b = a * b^(-1).
    #[inline]
    fn div(self, other: Self) -> Self {
        self.mul(other.inv())
    }
}

impl ConstantTimeEq for Gf256 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gf256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Polynomial Operations
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate polynomial at point x using Horner's method.
///
/// Coefficients are `[a₀, a₁, ..., aₖ₋₁]` for `a₀ + a₁·x + ... + aₖ₋₁·x^(k-1)`.
fn poly_eval(coefficients: &[Gf256], x: Gf256) -> Gf256 {
    if coefficients.is_empty() {
        return Gf256::new(0);
    }

    // Horner's method: ((a_{k-1} * x + a_{k-2}) * x + ...) * x + a_0
    let mut result = Gf256::new(0);
    for coeff in coefficients.iter().rev() {
        result = result.mul(x).add(*coeff);
    }
    result
}

/// Generate random polynomial with given constant term (the secret byte).
fn random_poly<R: RngCore + CryptoRng>(rng: &mut R, constant: u8, degree: usize) -> Vec<Gf256> {
    let mut coefficients = Vec::with_capacity(degree + 1);
    coefficients.push(Gf256::new(constant)); // a_0 = secret

    for _ in 0..degree {
        coefficients.push(Gf256::new(rng.r#gen()));
    }

    coefficients
}

/// Lagrange interpolation at x=0 to recover the secret.
///
/// Given points `(xᵢ, yᵢ)`, computes `f(0)` where f is the unique polynomial of degree < k
/// passing through all points.
fn lagrange_interpolate_at_zero(points: &[(Gf256, Gf256)]) -> Gf256 {
    let mut result = Gf256::new(0);

    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        // Compute Lagrange basis polynomial L_i(0)
        // L_i(0) = ∏_{j≠i} (0 - x_j) / (x_i - x_j) = ∏_{j≠i} x_j / (x_i - x_j)
        // In GF(2^8), subtraction is XOR, so x_i - x_j = x_i ^ x_j
        let mut basis = Gf256::new(1);
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i != j {
                // Numerator: x_j (since 0 - x_j = x_j in GF(2^8))
                // Denominator: x_i - x_j = x_i ^ x_j
                let numerator = x_j;
                let denominator = x_i.sub(x_j);
                basis = basis.mul(numerator.div(denominator));
            }
        }

        // Add y_i * L_i(0) to result
        result = result.add(y_i.mul(basis));
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Split a secret into n shares, requiring k shares to reconstruct.
///
/// # Arguments
/// * `secret` - The secret bytes to split
/// * `k` - Threshold: minimum shares needed to reconstruct (1 ≤ k ≤ n)
/// * `n` - Total number of shares to create (k ≤ n ≤ 255)
///
/// # Returns
/// A vector of n `ShamirShare`s. Any k of these can reconstruct the secret.
///
/// # Errors
/// Returns error if parameters are invalid.
///
/// # Example
/// ```rust
/// use fcp_crypto::shamir::split_secret;
///
/// let secret = b"encryption key";
/// let shares = split_secret(secret, 3, 5).unwrap();
/// assert_eq!(shares.len(), 5);
/// ```
pub fn split_secret(secret: &[u8], k: u8, n: u8) -> ShamirResult<Vec<ShamirShare>> {
    split_secret_with_rng(&mut rand::thread_rng(), secret, k, n)
}

/// Split a secret using a provided RNG (for testing/determinism).
///
/// # Errors
///
/// Returns error if:
/// - `k` is 0 (threshold must be at least 1)
/// - `k > n` (threshold cannot exceed total shares)
/// - `secret` is empty
pub fn split_secret_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &[u8],
    k: u8,
    n: u8,
) -> ShamirResult<Vec<ShamirShare>> {
    // Validate parameters
    if k == 0 {
        return Err(ShamirError::ThresholdTooSmall);
    }
    if k > n {
        return Err(ShamirError::ThresholdExceedsTotal {
            threshold: k,
            total: n,
        });
    }
    if n == 0 {
        return Err(ShamirError::TooManyShares);
    }
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    let degree = usize::from(k) - 1;

    // Create shares
    let mut shares: Vec<ShamirShare> = (1..=n)
        .map(|index| ShamirShare::new(index, Vec::with_capacity(secret.len())))
        .collect();

    // For each byte of the secret, create a random polynomial and evaluate at each x
    for &secret_byte in secret {
        let mut poly = random_poly(rng, secret_byte, degree);

        for share in &mut shares {
            let x = Gf256::new(share.index);
            let y = poly_eval(&poly, x);
            share.data.push(y.value());
        }

        // Zeroize polynomial coefficients to prevent leaking random values
        // (The constant term equals secret_byte which is already in the input)
        poly.zeroize();
    }

    Ok(shares)
}

/// Reconstruct a secret from k or more shares.
///
/// # Arguments
/// * `shares` - At least k shares from the original split
///
/// # Returns
/// The reconstructed secret bytes, wrapped in a zeroizing container.
///
/// # Errors
/// Returns error if shares are invalid or inconsistent.
///
/// # Security Note
/// The returned secret is wrapped in a `ZeroizingSecret` that will be
/// securely erased when dropped.
///
/// # Example
/// ```rust
/// use fcp_crypto::shamir::{split_secret, reconstruct_secret};
///
/// let secret = b"my secret";
/// let shares = split_secret(secret, 3, 5).unwrap();
///
/// // Use any 3 shares
/// let subset: Vec<_> = shares.into_iter().take(3).collect();
/// let recovered = reconstruct_secret(&subset).unwrap();
///
/// assert_eq!(&recovered[..], secret);
/// ```
pub fn reconstruct_secret(shares: &[ShamirShare]) -> ShamirResult<ZeroizingSecret> {
    if shares.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    // Check for duplicate indices
    let mut seen = [false; 256];
    for share in shares {
        if share.index == 0 {
            return Err(ShamirError::ReservedIndex);
        }
        if seen[usize::from(share.index)] {
            return Err(ShamirError::DuplicateIndex(share.index));
        }
        seen[usize::from(share.index)] = true;
    }

    // Verify all shares have the same length
    let secret_len = shares[0].data.len();
    if shares.iter().any(|s| s.data.len() != secret_len) {
        return Err(ShamirError::MismatchedLengths);
    }

    // Reconstruct each byte of the secret
    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let points: Vec<(Gf256, Gf256)> = shares
            .iter()
            .map(|s| (Gf256::new(s.index), Gf256::new(s.data[byte_idx])))
            .collect();

        let recovered = lagrange_interpolate_at_zero(&points);
        secret.push(recovered.value());
    }

    Ok(ZeroizingSecret(secret))
}

/// Wrapper for reconstructed secret that zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingSecret(Vec<u8>);

impl ZeroizingSecret {
    /// Access the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
}

impl std::ops::Deref for ZeroizingSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for ZeroizingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroizingSecret")
            .field("len", &self.0.len())
            .field("data", &"[redacted]")
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HPKE Integration for Share Sealing
// ─────────────────────────────────────────────────────────────────────────────

use crate::error::CryptoResult;
use crate::hpke_seal::{Fcp2Aad, HpkeSealedBox, hpke_open, hpke_seal};
use crate::x25519::{X25519PublicKey, X25519SecretKey};

/// A sealed Shamir share, encrypted to a specific node's X25519 key.
///
/// Contains the share index and HPKE-sealed share data.
#[derive(Clone, Debug)]
pub struct SealedShamirShare {
    /// Share index (1-based).
    index: u8,
    /// HPKE sealed box containing the share data.
    sealed_box: HpkeSealedBox,
}

impl SealedShamirShare {
    /// Get the share index.
    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Get the sealed box.
    #[must_use]
    pub const fn sealed_box(&self) -> &HpkeSealedBox {
        &self.sealed_box
    }

    /// Convert to raw bytes (for storage/transmission).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(1 + self.sealed_box.enc.len() + self.sealed_box.ciphertext.len());
        bytes.push(self.index);
        bytes.extend_from_slice(&self.sealed_box.enc);
        bytes.extend_from_slice(&self.sealed_box.ciphertext);
        bytes
    }
}

/// Seal a Shamir share to a node's X25519 public key using HPKE.
///
/// The sealed share can only be decrypted by the holder of the corresponding
/// secret key. AAD binds the share to the zone and recipient.
///
/// # Arguments
/// * `share` - The Shamir share to seal
/// * `recipient_pk` - The recipient node's X25519 public key
/// * `zone_id` - The zone identifier (for AAD binding)
/// * `recipient_node_id` - The recipient node identifier (for AAD binding)
/// * `issued_at` - Timestamp (Unix seconds) for AAD binding
///
/// # Errors
/// Returns error if HPKE sealing fails.
pub fn seal_share(
    share: &ShamirShare,
    recipient_pk: &X25519PublicKey,
    zone_id: &[u8],
    recipient_node_id: &[u8],
    issued_at: u64,
) -> CryptoResult<SealedShamirShare> {
    let aad = Fcp2Aad::for_secret_share(zone_id, recipient_node_id, issued_at);
    let sealed_box = hpke_seal(recipient_pk, share.data(), &aad)?;
    Ok(SealedShamirShare {
        index: share.index(),
        sealed_box,
    })
}

/// Open a sealed Shamir share using the recipient's X25519 secret key.
///
/// # Arguments
/// * `sealed_share` - The sealed share to open
/// * `recipient_sk` - The recipient node's X25519 secret key
/// * `zone_id` - The zone identifier (must match sealing AAD)
/// * `recipient_node_id` - The recipient node identifier (must match sealing AAD)
/// * `issued_at` - Timestamp (must match sealing AAD)
///
/// # Errors
/// Returns error if HPKE opening fails (wrong key, tampered data, or wrong AAD).
pub fn open_share(
    sealed_share: &SealedShamirShare,
    recipient_sk: &X25519SecretKey,
    zone_id: &[u8],
    recipient_node_id: &[u8],
    issued_at: u64,
) -> CryptoResult<ShamirShare> {
    let aad = Fcp2Aad::for_secret_share(zone_id, recipient_node_id, issued_at);
    let data = hpke_open(recipient_sk, sealed_share.sealed_box(), &aad)?;
    Ok(ShamirShare::new(sealed_share.index(), data))
}

/// Split a secret and seal each share to a different node.
///
/// This is a convenience function that combines `split_secret` with `seal_share`.
///
/// # Arguments
/// * `secret` - The secret bytes to split
/// * `k` - Threshold: minimum shares needed to reconstruct
/// * `recipients` - List of `(node_id, public_key)` tuples, one per share
/// * `zone_id` - The zone identifier for AAD binding
/// * `issued_at` - Timestamp for AAD binding
///
/// # Errors
/// Returns error if splitting or sealing fails.
pub fn split_and_seal(
    secret: &[u8],
    k: u8,
    recipients: &[(&[u8], &X25519PublicKey)],
    zone_id: &[u8],
    issued_at: u64,
) -> ShamirResult<Vec<SealedShamirShare>> {
    let n = recipients
        .len()
        .try_into()
        .map_err(|_| ShamirError::TooManyShares)?;

    let shares = split_secret(secret, k, n)?;

    let mut sealed_shares = Vec::with_capacity(recipients.len());
    for (share, (node_id, pk)) in shares.iter().zip(recipients.iter()) {
        let sealed = seal_share(share, pk, zone_id, node_id, issued_at)
            .map_err(|e| ShamirError::SealingFailed(e.to_string()))?;
        sealed_shares.push(sealed);
    }

    Ok(sealed_shares)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn deterministic_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([0x42; 32])
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GF(2^8) Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn gf256_add_is_xor() {
        let a = Gf256::new(0b1010_1010);
        let b = Gf256::new(0b1100_1100);
        assert_eq!(a.add(b).value(), 0b1010_1010 ^ 0b1100_1100);
    }

    #[test]
    fn gf256_add_is_self_inverse() {
        let a = Gf256::new(123);
        assert_eq!(a.add(a).value(), 0);
    }

    #[test]
    fn gf256_mul_identity() {
        let a = Gf256::new(42);
        let one = Gf256::new(1);
        assert_eq!(a.mul(one).value(), 42);
    }

    #[test]
    fn gf256_mul_zero() {
        let a = Gf256::new(42);
        let zero = Gf256::new(0);
        assert_eq!(a.mul(zero).value(), 0);
    }

    #[test]
    fn gf256_mul_commutative() {
        let a = Gf256::new(0x53);
        let b = Gf256::new(0xCA);
        assert_eq!(a.mul(b).value(), b.mul(a).value());
    }

    #[test]
    fn gf256_mul_known_value() {
        // Test vector from AES: 0x57 * 0x83 = 0xC1
        let a = Gf256::new(0x57);
        let b = Gf256::new(0x83);
        assert_eq!(a.mul(b).value(), 0xC1);
    }

    #[test]
    fn gf256_inv_property() {
        // For all non-zero elements, a * a^(-1) = 1
        for i in 1..=255u8 {
            let a = Gf256::new(i);
            let inv = a.inv();
            assert_eq!(a.mul(inv).value(), 1, "inverse failed for {i}");
        }
    }

    #[test]
    fn gf256_div_reverses_mul() {
        let a = Gf256::new(42);
        let b = Gf256::new(17);
        let product = a.mul(b);
        assert_eq!(product.div(b).value(), a.value());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Polynomial Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn poly_eval_constant() {
        let coeffs = vec![Gf256::new(42)];
        assert_eq!(poly_eval(&coeffs, Gf256::new(0)).value(), 42);
        assert_eq!(poly_eval(&coeffs, Gf256::new(100)).value(), 42);
    }

    #[test]
    fn poly_eval_at_zero_returns_constant() {
        let coeffs = vec![Gf256::new(7), Gf256::new(3), Gf256::new(5)];
        // f(x) = 7 + 3x + 5x^2
        // f(0) = 7
        assert_eq!(poly_eval(&coeffs, Gf256::new(0)).value(), 7);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Split and Reconstruct Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn split_reconstruct_basic() {
        let secret = b"hello world";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly k shares
        let subset: Vec<_> = shares[0..3].to_vec();
        let recovered = reconstruct_secret(&subset).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    #[test]
    fn split_reconstruct_all_shares() {
        let secret = b"secret key";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Using all shares should also work
        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    #[test]
    fn split_reconstruct_different_subsets() {
        let mut rng = deterministic_rng();
        let secret = b"test secret 123";
        let shares = split_secret_with_rng(&mut rng, secret, 3, 5).unwrap();

        // Any 3 of 5 shares should reconstruct the secret
        let combinations = [
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for indices in combinations {
            let subset: Vec<_> = indices.iter().map(|&i| shares[i].clone()).collect();
            let recovered = reconstruct_secret(&subset).unwrap();
            assert_eq!(&recovered[..], secret, "failed for indices {indices:?}");
        }
    }

    #[test]
    fn split_reconstruct_2_of_2() {
        let secret = b"minimal";
        let shares = split_secret(secret, 2, 2).unwrap();
        assert_eq!(shares.len(), 2);

        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    #[test]
    fn split_reconstruct_1_of_n() {
        // k=1 means the secret is just copied (no security, but valid)
        let secret = b"not secure";
        let shares = split_secret(secret, 1, 3).unwrap();

        // Any single share should reconstruct
        for share in &shares {
            let recovered = reconstruct_secret(std::slice::from_ref(share)).unwrap();
            assert_eq!(&recovered[..], secret);
        }
    }

    #[test]
    fn split_reconstruct_n_of_n() {
        let secret = b"all required";
        let shares = split_secret(secret, 5, 5).unwrap();

        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn split_reconstruct_long_secret() {
        let secret: Vec<u8> = (0..1024u16).map(|i| (i % 256) as u8).collect();
        let shares = split_secret(&secret, 5, 10).unwrap();

        let subset: Vec<_> = shares[3..8].to_vec();
        let recovered = reconstruct_secret(&subset).unwrap();
        assert_eq!(&recovered[..], &secret[..]);
    }

    #[test]
    fn split_reconstruct_single_byte() {
        let secret = b"X";
        let shares = split_secret(secret, 3, 5).unwrap();

        let subset: Vec<_> = shares[1..4].to_vec();
        let recovered = reconstruct_secret(&subset).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error Cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn split_error_threshold_zero() {
        let result = split_secret(b"test", 0, 5);
        assert!(matches!(result, Err(ShamirError::ThresholdTooSmall)));
    }

    #[test]
    fn split_error_threshold_exceeds_total() {
        let result = split_secret(b"test", 6, 5);
        assert!(matches!(
            result,
            Err(ShamirError::ThresholdExceedsTotal {
                threshold: 6,
                total: 5
            })
        ));
    }

    #[test]
    fn split_error_empty_secret() {
        let result = split_secret(b"", 3, 5);
        assert!(matches!(result, Err(ShamirError::EmptySecret)));
    }

    #[test]
    fn reconstruct_error_duplicate_index() {
        let shares = vec![
            ShamirShare::new(1, vec![1, 2, 3]),
            ShamirShare::new(1, vec![4, 5, 6]), // duplicate index
        ];
        let result = reconstruct_secret(&shares);
        assert!(matches!(result, Err(ShamirError::DuplicateIndex(1))));
    }

    #[test]
    fn reconstruct_error_mismatched_lengths() {
        let shares = vec![
            ShamirShare::new(1, vec![1, 2, 3]),
            ShamirShare::new(2, vec![4, 5]), // different length
        ];
        let result = reconstruct_secret(&shares);
        assert!(matches!(result, Err(ShamirError::MismatchedLengths)));
    }

    #[test]
    fn reconstruct_error_empty_shares() {
        let result = reconstruct_secret(&[]);
        assert!(matches!(result, Err(ShamirError::EmptySecret)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn share_serialization_roundtrip() {
        let share = ShamirShare::new(42, vec![1, 2, 3, 4, 5]);
        let bytes = share.to_bytes();
        let recovered = ShamirShare::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.index(), 42);
        assert_eq!(recovered.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn share_from_bytes_error_empty() {
        let result = ShamirShare::from_bytes(&[]);
        assert!(matches!(result, Err(ShamirError::EmptySecret)));
    }

    #[test]
    fn share_from_bytes_error_reserved_index() {
        let result = ShamirShare::from_bytes(&[0, 1, 2, 3]);
        assert!(matches!(result, Err(ShamirError::ReservedIndex)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Security Property Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn share_debug_redacts_data() {
        let share = ShamirShare::new(1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{share:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
    }

    #[test]
    fn zeroizing_secret_debug_redacts() {
        let secret = ZeroizingSecret(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
    }

    #[test]
    fn insufficient_shares_give_wrong_result() {
        // With k-1 shares, reconstruction should give wrong answer
        // (This tests the information-theoretic security property)
        let mut rng = deterministic_rng();
        let secret = b"my secret!";
        let shares = split_secret_with_rng(&mut rng, secret, 3, 5).unwrap();

        // Using only 2 shares (k-1)
        let subset: Vec<_> = shares[0..2].to_vec();
        let recovered = reconstruct_secret(&subset).unwrap();

        // Should NOT equal the original secret
        assert_ne!(&recovered[..], secret);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Determinism Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn same_rng_produces_same_shares() {
        let secret = b"deterministic test";

        let mut rng1 = deterministic_rng();
        let shares1 = split_secret_with_rng(&mut rng1, secret, 3, 5).unwrap();

        let mut rng2 = deterministic_rng();
        let shares2 = split_secret_with_rng(&mut rng2, secret, 3, 5).unwrap();

        for (s1, s2) in shares1.iter().zip(shares2.iter()) {
            assert_eq!(s1.index(), s2.index());
            assert_eq!(s1.data(), s2.data());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HPKE Sealing/Opening Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn seal_and_open_share_roundtrip() {
        use crate::x25519::X25519SecretKey;

        let secret = b"test secret";
        let shares = split_secret(secret, 2, 3).unwrap();

        // Generate a key pair for the recipient
        let recipient_sk = X25519SecretKey::generate();
        let recipient_pk = recipient_sk.public_key();

        let zone_id = b"z:test-zone";
        let node_id = b"node:alice";
        let issued_at = 1_700_000_000u64;

        // Seal the first share
        let sealed = seal_share(&shares[0], &recipient_pk, zone_id, node_id, issued_at).unwrap();
        assert_eq!(sealed.index(), shares[0].index());

        // Open the sealed share
        let opened = open_share(&sealed, &recipient_sk, zone_id, node_id, issued_at).unwrap();
        assert_eq!(opened.index(), shares[0].index());
        assert_eq!(opened.data(), shares[0].data());
    }

    #[test]
    fn seal_open_reconstruct_full_workflow() {
        use crate::x25519::X25519SecretKey;

        let secret = b"my distributed secret";
        let k = 3u8;
        let n = 5u8;

        // Generate key pairs for each node
        let keys: Vec<_> = (0..n).map(|_| X25519SecretKey::generate()).collect();
        let zone_id = b"z:production";
        let issued_at = 1_700_000_000u64;

        // Split the secret
        let shares = split_secret(secret, k, n).unwrap();

        // Seal each share to its respective node
        let sealed_shares: Vec<_> = shares
            .iter()
            .zip(keys.iter())
            .enumerate()
            .map(|(i, (share, sk))| {
                let pk = sk.public_key();
                let node_id = format!("node:{i}");
                seal_share(share, &pk, zone_id, node_id.as_bytes(), issued_at).unwrap()
            })
            .collect();

        // Pick any k sealed shares and open them
        let selected_indices = [0usize, 2, 4];
        let opened_shares: Vec<_> = selected_indices
            .iter()
            .map(|&i| {
                let node_id = format!("node:{i}");
                open_share(
                    &sealed_shares[i],
                    &keys[i],
                    zone_id,
                    node_id.as_bytes(),
                    issued_at,
                )
                .unwrap()
            })
            .collect();

        // Reconstruct the secret
        let recovered = reconstruct_secret(&opened_shares).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    #[test]
    fn split_and_seal_convenience() {
        use crate::x25519::X25519SecretKey;

        let secret = b"convenient secret";
        let k = 2u8;

        // Generate key pairs for 3 nodes
        let keys: Vec<_> = (0..3).map(|_| X25519SecretKey::generate()).collect();
        let node_ids: Vec<Vec<u8>> = (0..3).map(|i| format!("node:{i}").into_bytes()).collect();
        let zone_id = b"z:convenience";
        let issued_at = 1_700_000_000u64;

        // Store public keys first (need owned values for borrowing)
        let pks: Vec<_> = keys.iter().map(X25519SecretKey::public_key).collect();
        let recipients: Vec<(&[u8], &crate::x25519::X25519PublicKey)> = node_ids
            .iter()
            .zip(pks.iter())
            .map(|(node_id, pk)| (node_id.as_slice(), pk))
            .collect();

        let sealed = split_and_seal(secret, k, &recipients, zone_id, issued_at).unwrap();
        assert_eq!(sealed.len(), 3);

        // Open first 2 shares and reconstruct
        let opened: Vec<_> = (0..2)
            .map(|i| {
                open_share(
                    &sealed[i],
                    &keys[i],
                    zone_id,
                    node_ids[i].as_slice(),
                    issued_at,
                )
                .unwrap()
            })
            .collect();

        let recovered = reconstruct_secret(&opened).unwrap();
        assert_eq!(&recovered[..], secret);
    }

    #[test]
    fn open_share_wrong_key_fails() {
        use crate::x25519::X25519SecretKey;

        let secret = b"test";
        let shares = split_secret(secret, 2, 3).unwrap();

        let correct_sk = X25519SecretKey::generate();
        let wrong_sk = X25519SecretKey::generate();
        let correct_pk = correct_sk.public_key();

        let zone_id = b"z:test";
        let node_id = b"node:1";
        let issued_at = 1_700_000_000u64;

        let sealed = seal_share(&shares[0], &correct_pk, zone_id, node_id, issued_at).unwrap();

        // Opening with wrong key should fail
        let result = open_share(&sealed, &wrong_sk, zone_id, node_id, issued_at);
        assert!(result.is_err());
    }

    #[test]
    fn open_share_wrong_aad_fails() {
        use crate::x25519::X25519SecretKey;

        let secret = b"test";
        let shares = split_secret(secret, 2, 3).unwrap();

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_id = b"z:test";
        let node_id = b"node:1";
        let issued_at = 1_700_000_000u64;

        let sealed = seal_share(&shares[0], &pk, zone_id, node_id, issued_at).unwrap();

        // Opening with different zone should fail
        let result = open_share(&sealed, &sk, b"z:wrong", node_id, issued_at);
        assert!(result.is_err());

        // Opening with different node_id should fail
        let result = open_share(&sealed, &sk, zone_id, b"node:wrong", issued_at);
        assert!(result.is_err());

        // Opening with different timestamp should fail
        let result = open_share(&sealed, &sk, zone_id, node_id, 1_800_000_000u64);
        assert!(result.is_err());
    }
}
