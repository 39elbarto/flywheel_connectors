//! Regression for br-1zlht (security audit B3).
//!
//! Pins that the secret-bearing PQ types in `fcp-crypto` use
//! constant-time equality (via `subtle::ConstantTimeEq`) instead of the
//! short-circuit `Vec<u8>::eq` / `[u8; N]::eq` derived `PartialEq`.
//!
//! A full timing-side-channel test is impractical in a unit test (the
//! signal is sub-microsecond and noise dominates), so this file pins
//! the *behavioural* properties that are byproducts of using
//! constant-time equality:
//!
//! 1. Equality on equal inputs returns true.
//! 2. Equality on unequal inputs returns false.
//! 3. Equality is reflexive, symmetric, transitive.
//! 4. **The implementation does NOT use the derived `Vec<u8>::eq`** —
//!    pinned by exercising a "first-byte differs" vs "last-byte
//!    differs" pair and asserting both return false (a derived
//!    short-circuit would still return the correct answer; this
//!    documents intent).
//!
//! For the load-bearing assurance — that the implementation calls
//! `subtle::ConstantTimeEq::ct_eq` and not a short-circuit byte
//! compare — see the source code at
//! `crates/fcp-crypto/src/owner_key.rs::MlDsa65VerifyingKeyBytes::eq`,
//! `crates/fcp-crypto/src/owner_key.rs::MlDsa65SignatureBytes::eq`,
//! and `crates/fcp-crypto/src/xwing.rs::XWingSecretKey::eq`.

use fcp_crypto::{
    XWING_SECRET_KEY_SIZE, XWingSecretKey,
    owner_key::{
        ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes,
        MlDsa65VerifyingKeyBytes,
    },
};

// ── XWingSecretKey ──────────────────────────────────────────────────

#[test]
fn xwing_secret_key_eq_reflects_byte_equality() {
    let a = XWingSecretKey::from_bytes(&[0x42; XWING_SECRET_KEY_SIZE]).unwrap();
    let b = XWingSecretKey::from_bytes(&[0x42; XWING_SECRET_KEY_SIZE]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn xwing_secret_key_eq_distinguishes_first_byte_diff() {
    let mut bytes_a = [0x42; XWING_SECRET_KEY_SIZE];
    let mut bytes_b = [0x42; XWING_SECRET_KEY_SIZE];
    bytes_b[0] = 0xFF;
    let a = XWingSecretKey::from_bytes(&bytes_a).unwrap();
    let b = XWingSecretKey::from_bytes(&bytes_b).unwrap();
    assert_ne!(a, b);
    bytes_a[0] = 0xFF;
    let a2 = XWingSecretKey::from_bytes(&bytes_a).unwrap();
    assert_eq!(a2, b);
}

#[test]
fn xwing_secret_key_eq_distinguishes_last_byte_diff() {
    // br-1zlht: a derived short-circuit eq would return the correct
    // answer here just like the constant-time eq. The point of the
    // test is to pin that the value does not silently regress to
    // "all comparisons return true" — the constant-time impl must
    // still detect the mismatch.
    let mut bytes_a = [0x42; XWING_SECRET_KEY_SIZE];
    let mut bytes_b = [0x42; XWING_SECRET_KEY_SIZE];
    bytes_b[XWING_SECRET_KEY_SIZE - 1] = 0xFF;
    let a = XWingSecretKey::from_bytes(&bytes_a).unwrap();
    let b = XWingSecretKey::from_bytes(&bytes_b).unwrap();
    assert_ne!(a, b);
    bytes_a[XWING_SECRET_KEY_SIZE - 1] = 0xFF;
    let a2 = XWingSecretKey::from_bytes(&bytes_a).unwrap();
    assert_eq!(a2, b);
}

#[test]
fn xwing_secret_key_eq_is_reflexive_symmetric_transitive() {
    let a = XWingSecretKey::from_bytes(&[0xAA; XWING_SECRET_KEY_SIZE]).unwrap();
    let b = XWingSecretKey::from_bytes(&[0xAA; XWING_SECRET_KEY_SIZE]).unwrap();
    let c = XWingSecretKey::from_bytes(&[0xAA; XWING_SECRET_KEY_SIZE]).unwrap();
    assert_eq!(a, a);
    assert_eq!(a, b);
    assert_eq!(b, a);
    assert!(a == b && b == c && a == c);
}

// ── MlDsa65SignatureBytes ───────────────────────────────────────────

#[test]
fn ml_dsa_signature_bytes_eq_reflects_byte_equality() {
    let a = MlDsa65SignatureBytes::try_from_bytes(vec![0x33; ML_DSA_65_SIGNATURE_SIZE]).unwrap();
    let b = MlDsa65SignatureBytes::try_from_bytes(vec![0x33; ML_DSA_65_SIGNATURE_SIZE]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn ml_dsa_signature_bytes_eq_distinguishes_diff() {
    let a = MlDsa65SignatureBytes::try_from_bytes(vec![0x33; ML_DSA_65_SIGNATURE_SIZE]).unwrap();
    let mut other = vec![0x33; ML_DSA_65_SIGNATURE_SIZE];
    other[ML_DSA_65_SIGNATURE_SIZE / 2] = 0xFF;
    let b = MlDsa65SignatureBytes::try_from_bytes(other).unwrap();
    assert_ne!(a, b);
}

#[test]
fn ml_dsa_signature_bytes_eq_no_panic_on_round_trip_compare() {
    let bytes = vec![0xAB; ML_DSA_65_SIGNATURE_SIZE];
    let a = MlDsa65SignatureBytes::try_from_bytes(bytes.clone()).unwrap();
    let b = MlDsa65SignatureBytes::try_from_bytes(bytes).unwrap();
    assert_eq!(a, b, "identical bytes must compare equal");
}

// ── MlDsa65VerifyingKeyBytes ────────────────────────────────────────

#[test]
fn ml_dsa_verifying_key_bytes_eq_reflects_byte_equality() {
    let a =
        MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0x77; ML_DSA_65_PUBLIC_KEY_SIZE]).unwrap();
    let b =
        MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0x77; ML_DSA_65_PUBLIC_KEY_SIZE]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn ml_dsa_verifying_key_bytes_eq_distinguishes_diff() {
    let a =
        MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0x77; ML_DSA_65_PUBLIC_KEY_SIZE]).unwrap();
    let mut other = vec![0x77; ML_DSA_65_PUBLIC_KEY_SIZE];
    other[ML_DSA_65_PUBLIC_KEY_SIZE / 2] = 0xFF;
    let b = MlDsa65VerifyingKeyBytes::try_from_bytes(other).unwrap();
    assert_ne!(a, b);
}

// ── Smoke-test that the workspace still uses subtle::ConstantTimeEq

#[test]
fn subtle_crate_is_available_and_exports_ct_eq() {
    // br-1zlht: if a future workspace edit removes the `subtle` dep,
    // every constant-time PartialEq impl in fcp-crypto / fcp-crypto-pq
    // would silently regress to a derive. This smoke test pins that
    // subtle::ConstantTimeEq is in scope and behaves as expected for
    // a 32-byte slice.
    use subtle::ConstantTimeEq;
    let a = [0xAB_u8; 32];
    let b = [0xAB_u8; 32];
    let mut c = [0xAB_u8; 32];
    c[0] = 0xFF;
    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
}
