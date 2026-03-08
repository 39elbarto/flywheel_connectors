//! PKCE (Proof Key for Code Exchange) implementation.
//!
//! PKCE is an extension to OAuth 2.0 that prevents authorization code
//! interception attacks.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::OAuthError;

/// PKCE code challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PkceMethod {
    /// Plain text (not recommended).
    Plain,
    /// SHA-256 hash (recommended).
    #[default]
    S256,
}

impl std::fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::S256 => write!(f, "S256"),
        }
    }
}

/// PKCE verifier and challenge pair.
#[derive(Debug, Clone)]
pub struct Pkce {
    /// The code verifier (secret, sent during token exchange).
    verifier: String,
    /// The code challenge (sent during authorization).
    challenge: String,
    /// The challenge method used.
    method: PkceMethod,
}

impl Pkce {
    /// Generate a new PKCE pair using S256 method.
    #[must_use]
    pub fn new() -> Self {
        Self::with_method(PkceMethod::S256)
    }

    /// Generate a new PKCE pair with specified method.
    #[must_use]
    pub fn with_method(method: PkceMethod) -> Self {
        let verifier = Self::generate_verifier();
        let challenge = Self::compute_challenge(&verifier, method);

        Self {
            verifier,
            challenge,
            method,
        }
    }

    /// Create from an existing verifier.
    ///
    /// # Errors
    ///
    /// Returns error if verifier is invalid.
    pub fn from_verifier(verifier: &str, method: PkceMethod) -> Result<Self, OAuthError> {
        // Validate verifier length (43-128 characters per RFC 7636)
        if verifier.len() < 43 || verifier.len() > 128 {
            return Err(OAuthError::PkceError(format!(
                "Verifier must be 43-128 characters, got {}",
                verifier.len()
            )));
        }

        // Validate verifier characters (unreserved characters only)
        if !verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(OAuthError::PkceError(
                "Verifier contains invalid characters".to_string(),
            ));
        }

        let challenge = Self::compute_challenge(verifier, method);

        Ok(Self {
            verifier: verifier.to_string(),
            challenge,
            method,
        })
    }

    /// Get the code verifier.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Get the code challenge.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Get the challenge method.
    #[must_use]
    pub const fn method(&self) -> PkceMethod {
        self.method
    }

    /// Generate a cryptographically random verifier.
    fn generate_verifier() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Compute the challenge from a verifier.
    fn compute_challenge(verifier: &str, method: PkceMethod) -> String {
        match method {
            PkceMethod::Plain => verifier.to_string(),
            PkceMethod::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                URL_SAFE_NO_PAD.encode(hash)
            }
        }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let pkce = Pkce::new();

        // Verifier should be base64url encoded (43 chars for 32 bytes)
        assert_eq!(pkce.verifier().len(), 43);
        assert_eq!(pkce.method(), PkceMethod::S256);

        // Challenge should be different from verifier for S256
        assert_ne!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn test_pkce_plain() {
        let pkce = Pkce::with_method(PkceMethod::Plain);

        // For plain method, challenge equals verifier
        assert_eq!(pkce.verifier(), pkce.challenge());
        assert_eq!(pkce.method(), PkceMethod::Plain);
    }

    #[test]
    fn test_pkce_from_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();

        assert_eq!(pkce.verifier(), verifier);
        // Known challenge for this verifier
        assert_eq!(
            pkce.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn test_pkce_invalid_verifier() {
        // Too short
        let result = Pkce::from_verifier("short", PkceMethod::S256);
        assert!(result.is_err());

        // Invalid characters
        let result = Pkce::from_verifier(&"a".repeat(50).replace('a', " "), PkceMethod::S256);
        assert!(result.is_err());
    }

    // ── New tests ──

    #[test]
    fn test_pkce_method_display() {
        assert_eq!(PkceMethod::Plain.to_string(), "plain");
        assert_eq!(PkceMethod::S256.to_string(), "S256");
    }

    #[test]
    fn test_pkce_method_default_is_s256() {
        assert_eq!(PkceMethod::default(), PkceMethod::S256);
    }

    #[test]
    fn test_pkce_default_trait() {
        let pkce = Pkce::default();
        assert_eq!(pkce.method(), PkceMethod::S256);
        assert_eq!(pkce.verifier().len(), 43);
        assert_ne!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn test_pkce_verifier_too_long() {
        let long = "a".repeat(129);
        let result = Pkce::from_verifier(&long, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_verifier_exact_min() {
        let exact_min = "a".repeat(43);
        let result = Pkce::from_verifier(&exact_min, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_verifier_exact_max() {
        let exact_max = "a".repeat(128);
        let result = Pkce::from_verifier(&exact_max, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_plain_challenge_equals_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let pkce = Pkce::from_verifier(verifier, PkceMethod::Plain).unwrap();
        assert_eq!(pkce.verifier(), pkce.challenge());
    }

    // ── Batch: uniqueness + format ──

    #[test]
    fn test_pkce_multiple_generations_produce_different_verifiers() {
        let p1 = Pkce::new();
        let p2 = Pkce::new();
        let p3 = Pkce::new();
        assert_ne!(p1.verifier(), p2.verifier());
        assert_ne!(p2.verifier(), p3.verifier());
    }

    #[test]
    fn test_pkce_s256_challenge_is_base64url() {
        let pkce = Pkce::new();
        let challenge = pkce.challenge();
        // S256 challenge: SHA-256(verifier) → base64url no padding
        // Should be 43 chars (32 bytes → base64url = ceil(32*4/3) = 43)
        assert_eq!(challenge.len(), 43);
        assert!(
            challenge
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_pkce_s256_challenge_no_padding() {
        let pkce = Pkce::new();
        assert!(!pkce.challenge().contains('='));
    }

    #[test]
    fn test_pkce_verifier_is_valid_base64url() {
        let pkce = Pkce::new();
        assert!(
            pkce.verifier()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    // ── Batch: from_verifier boundary validation ──

    #[test]
    fn test_pkce_from_verifier_exactly_42_chars_rejected() {
        let too_short = "a".repeat(42);
        let result = Pkce::from_verifier(&too_short, PkceMethod::S256);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("43-128"));
    }

    #[test]
    fn test_pkce_from_verifier_exactly_129_chars_rejected() {
        let too_long = "a".repeat(129);
        let result = Pkce::from_verifier(&too_long, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_all_valid_unreserved_chars() {
        // RFC 7636: verifier can contain [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        let verifier = "abcdefghijklmnopqrstuvwxyz-._~ABCDEFGHIJ01234";
        assert_eq!(verifier.len(), 45); // > 43
        let result = Pkce::from_verifier(verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_plus() {
        let verifier = "a".repeat(42) + "+";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn test_pkce_from_verifier_rejects_slash() {
        let verifier = "a".repeat(42) + "/";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_space() {
        let verifier = "a".repeat(42) + " ";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    // ── Batch: clone + debug ──

    #[test]
    fn test_pkce_clone() {
        let pkce = Pkce::new();
        let cloned = pkce.clone();
        assert_eq!(pkce.verifier(), cloned.verifier());
        assert_eq!(pkce.challenge(), cloned.challenge());
        assert_eq!(pkce.method(), cloned.method());
    }

    #[test]
    fn test_pkce_debug() {
        let pkce = Pkce::new();
        let debug = format!("{pkce:?}");
        assert!(debug.contains("Pkce"));
    }

    #[test]
    fn test_pkce_method_copy() {
        let method = PkceMethod::S256;
        let copied = method;
        assert_eq!(method, copied);
    }

    #[test]
    fn test_pkce_method_eq() {
        assert_eq!(PkceMethod::S256, PkceMethod::S256);
        assert_eq!(PkceMethod::Plain, PkceMethod::Plain);
        assert_ne!(PkceMethod::S256, PkceMethod::Plain);
    }

    // ── Batch: known test vectors ──

    #[test]
    fn test_pkce_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
        assert_eq!(pkce.challenge(), expected_challenge);
    }

    #[test]
    fn test_pkce_s256_deterministic() {
        // Same verifier → same challenge
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let p1 = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
        let p2 = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
        assert_eq!(p1.challenge(), p2.challenge());
    }

    #[test]
    fn test_pkce_plain_from_verifier_deterministic() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let pkce = Pkce::from_verifier(verifier, PkceMethod::Plain).unwrap();
        assert_eq!(pkce.challenge(), verifier);
    }

    // ── Expanded tests: verifier character validation ──

    #[test]
    fn test_pkce_from_verifier_rejects_equals() {
        let verifier = "a".repeat(42) + "=";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_at_sign() {
        let verifier = "a".repeat(42) + "@";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_hash() {
        let verifier = "a".repeat(42) + "#";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_accepts_tilde() {
        // ~ is a valid unreserved character
        let verifier = "a".repeat(42) + "~";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_accepts_dot() {
        let verifier = "a".repeat(42) + ".";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_accepts_hyphen() {
        let verifier = "a".repeat(42) + "-";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_accepts_underscore() {
        let verifier = "a".repeat(42) + "_";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    // ── Expanded tests: different verifier lengths ──

    #[test]
    fn test_pkce_from_verifier_length_44() {
        let verifier = "b".repeat(44);
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_length_100() {
        let verifier = "c".repeat(100);
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_length_0_rejected() {
        let result = Pkce::from_verifier("", PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_length_1_rejected() {
        let result = Pkce::from_verifier("a", PkceMethod::S256);
        assert!(result.is_err());
    }

    // ── Expanded tests: challenge properties ──

    #[test]
    fn test_pkce_different_verifiers_produce_different_challenges() {
        let v1 = "a".repeat(43);
        let v2 = "b".repeat(43);
        let p1 = Pkce::from_verifier(&v1, PkceMethod::S256).unwrap();
        let p2 = Pkce::from_verifier(&v2, PkceMethod::S256).unwrap();
        assert_ne!(p1.challenge(), p2.challenge());
    }

    #[test]
    fn test_pkce_method_debug() {
        let debug_s256 = format!("{:?}", PkceMethod::S256);
        let debug_plain = format!("{:?}", PkceMethod::Plain);
        assert!(debug_s256.contains("S256"));
        assert!(debug_plain.contains("Plain"));
    }

    // ── Expanded: verifier entropy ──

    #[test]
    fn test_pkce_ten_generations_all_unique() {
        let verifiers: Vec<String> = (0..10).map(|_| Pkce::new().verifier().to_string()).collect();
        for i in 0..verifiers.len() {
            for j in (i + 1)..verifiers.len() {
                assert_ne!(verifiers[i], verifiers[j], "duplicate at {i} and {j}");
            }
        }
    }

    #[test]
    fn test_pkce_s256_challenge_length_always_43() {
        for _ in 0..5 {
            let pkce = Pkce::new();
            assert_eq!(pkce.challenge().len(), 43);
        }
    }

    #[test]
    fn test_pkce_plain_challenge_length_matches_verifier() {
        let pkce = Pkce::with_method(PkceMethod::Plain);
        assert_eq!(pkce.challenge().len(), pkce.verifier().len());
    }

    #[test]
    fn test_pkce_from_verifier_all_digits() {
        let verifier = "0123456789012345678901234567890123456789012";
        assert_eq!(verifier.len(), 43);
        let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
        assert_eq!(pkce.verifier(), verifier);
    }

    #[test]
    fn test_pkce_from_verifier_all_uppercase() {
        let verifier = "A".repeat(43);
        let pkce = Pkce::from_verifier(&verifier, PkceMethod::S256).unwrap();
        assert_eq!(pkce.verifier(), verifier);
    }

    #[test]
    fn test_pkce_from_verifier_all_lowercase() {
        let verifier = "z".repeat(43);
        let pkce = Pkce::from_verifier(&verifier, PkceMethod::S256).unwrap();
        assert_eq!(pkce.verifier(), verifier);
    }

    #[test]
    fn test_pkce_from_verifier_mixed_valid_chars() {
        let verifier = "aB3-._~aB3-._~aB3-._~aB3-._~aB3-._~aB3-._~z";
        assert!(verifier.len() >= 43);
        let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
        assert_eq!(pkce.verifier(), verifier);
    }

    #[test]
    fn test_pkce_from_verifier_rejects_backslash() {
        let verifier = "a".repeat(42) + "\\";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_curly_brace() {
        let verifier = "a".repeat(42) + "{";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_pipe() {
        let verifier = "a".repeat(42) + "|";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_rejects_percent() {
        let verifier = "a".repeat(42) + "%";
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkce_from_verifier_error_message_contains_length() {
        let result = Pkce::from_verifier("short", PkceMethod::S256);
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("43-128"));
        assert!(err_msg.contains('5'));
    }

    #[test]
    fn test_pkce_new_method_is_s256() {
        let pkce = Pkce::new();
        assert_eq!(pkce.method(), PkceMethod::S256);
    }

    #[test]
    fn test_pkce_with_method_plain_returns_plain() {
        let pkce = Pkce::with_method(PkceMethod::Plain);
        assert_eq!(pkce.method(), PkceMethod::Plain);
    }

    #[test]
    fn test_pkce_with_method_s256_returns_s256() {
        let pkce = Pkce::with_method(PkceMethod::S256);
        assert_eq!(pkce.method(), PkceMethod::S256);
    }

    #[test]
    fn test_pkce_clone_preserves_all_fields() {
        let pkce = Pkce::with_method(PkceMethod::Plain);
        let cloned = pkce.clone();
        assert_eq!(pkce.verifier(), cloned.verifier());
        assert_eq!(pkce.challenge(), cloned.challenge());
        assert_eq!(pkce.method(), cloned.method());
        // Use originals after clone
        assert!(!pkce.verifier().is_empty());
        assert!(!cloned.verifier().is_empty());
    }

    #[test]
    fn test_pkce_from_verifier_length_127() {
        let verifier = "x".repeat(127);
        let result = Pkce::from_verifier(&verifier, PkceMethod::S256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pkce_from_verifier_length_128_boundary() {
        let verifier = "y".repeat(128);
        let pkce = Pkce::from_verifier(&verifier, PkceMethod::S256).unwrap();
        assert_eq!(pkce.verifier().len(), 128);
    }
}
