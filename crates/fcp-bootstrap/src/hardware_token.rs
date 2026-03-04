//! Hardware token detection and integration.
//!
//! This module provides cross-platform support for detecting and using
//! hardware security modules (HSMs) and smart cards via PKCS#11.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Information about a detected hardware token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedToken {
    /// PKCS#11 provider library path.
    pub provider: PathBuf,

    /// Slot number.
    pub slot: u32,

    /// Token label.
    pub label: String,

    /// Manufacturer name.
    pub manufacturer: String,

    /// Token serial number.
    pub serial: String,

    /// Supported mechanisms.
    pub mechanisms: Vec<String>,
}

impl DetectedToken {
    /// Check if this token supports Ed25519.
    #[must_use]
    pub fn supports_ed25519(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| m.contains("ED25519") || m.contains("EDDSA"))
    }

    /// Check if this token supports ECDH for X25519.
    #[must_use]
    pub fn supports_x25519(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| m.contains("X25519") || m.contains("ECDH"))
    }
}

impl std::fmt::Display for DetectedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) [slot {}]",
            self.label, self.manufacturer, self.slot
        )
    }
}

/// Provider for hardware token operations.
pub trait HardwareTokenProvider: Send + Sync {
    /// List available tokens.
    fn list_tokens(&self) -> Vec<DetectedToken>;

    /// Generate an Ed25519 keypair on the token.
    ///
    /// # Errors
    ///
    /// Returns a token error if key generation fails or the token is unavailable.
    fn generate_keypair(
        &self,
        token: &DetectedToken,
        pin: &str,
        label: &str,
    ) -> Result<[u8; 32], TokenError>;

    /// Sign data with a key on the token.
    ///
    /// # Errors
    ///
    /// Returns a token error if signing fails or the token is unavailable.
    fn sign(
        &self,
        token: &DetectedToken,
        pin: &str,
        key_label: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, TokenError>;
}

/// Errors during token operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No tokens found.
    #[error("no hardware tokens detected")]
    NoTokens,

    /// Token not found.
    #[error("token not found: {0}")]
    TokenNotFound(String),

    /// Invalid PIN.
    #[error("invalid PIN")]
    InvalidPin,

    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Mechanism not supported.
    #[error("mechanism not supported: {0}")]
    UnsupportedMechanism(String),

    /// PKCS#11 error.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    /// Token disconnected during operation.
    #[error("token disconnected")]
    Disconnected,
}

/// Cross-platform token detector.
pub struct TokenDetector {
    /// Provider paths to search.
    provider_paths: Vec<PathBuf>,
}

impl TokenDetector {
    /// Create a new token detector with default provider paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider_paths: default_provider_paths(),
        }
    }

    /// Add a custom provider path.
    pub fn add_provider(&mut self, path: PathBuf) {
        self.provider_paths.push(path);
    }

    /// Detect all available tokens.
    #[must_use]
    pub fn detect_all(&self) -> Vec<DetectedToken> {
        let mut tokens = Vec::new();

        for provider in &self.provider_paths {
            if provider.exists() {
                tokens.extend(detect_tokens_for_provider(provider));
            }
        }

        tokens
    }

    /// Detect tokens that support the required mechanisms for FCP.
    #[must_use]
    pub fn detect_fcp_compatible(&self) -> Vec<DetectedToken> {
        self.detect_all()
            .into_iter()
            .filter(DetectedToken::supports_ed25519)
            .collect()
    }
}

impl Default for TokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default PKCS#11 provider paths for the current platform.
fn default_provider_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib64/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/x86_64-linux-gnu/libykcs11.so"),
            PathBuf::from("/usr/lib/libykcs11.so"),
        ]
    }

    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/usr/local/lib/opensc-pkcs11.so"),
            PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so"),
            PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"),
            PathBuf::from("/usr/local/lib/libykcs11.dylib"),
            PathBuf::from("/opt/homebrew/lib/libykcs11.dylib"),
        ]
    }

    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\Windows\System32\opensc-pkcs11.dll"),
            PathBuf::from(r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"),
            PathBuf::from(r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"),
        ]
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        vec![]
    }
}

/// Detect tokens for a specific PKCS#11 provider.
///
/// This is a stub implementation - a real implementation would use the
/// pkcs11 crate to interact with the provider.
fn detect_tokens_for_provider(provider: &PathBuf) -> Vec<DetectedToken> {
    // In a real implementation, we would:
    // 1. Load the PKCS#11 library
    // 2. Initialize it
    // 3. List available slots
    // 4. For each slot with a token, get token info
    // 5. Get supported mechanisms

    tracing::debug!(?provider, "Probing PKCS#11 provider");

    // For now, return empty - actual implementation would use pkcs11 crate
    Vec::new()
}

/// Mock token provider for testing.
#[cfg(test)]
pub mod mock {
    use super::*;

    /// A mock hardware token provider for testing.
    pub struct MockTokenProvider {
        tokens: Vec<DetectedToken>,
    }

    impl MockTokenProvider {
        /// Create a new mock provider with no tokens.
        #[must_use]
        pub fn new() -> Self {
            Self { tokens: Vec::new() }
        }

        /// Add a mock token.
        pub fn add_token(&mut self, token: DetectedToken) {
            self.tokens.push(token);
        }
    }

    impl Default for MockTokenProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HardwareTokenProvider for MockTokenProvider {
        fn list_tokens(&self) -> Vec<DetectedToken> {
            self.tokens.clone()
        }

        fn generate_keypair(
            &self,
            _token: &DetectedToken,
            _pin: &str,
            _label: &str,
        ) -> Result<[u8; 32], TokenError> {
            use rand::RngCore;
            // Generate a random public key for testing
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            Ok(key)
        }

        fn sign(
            &self,
            _token: &DetectedToken,
            _pin: &str,
            _key_label: &str,
            _data: &[u8],
        ) -> Result<Vec<u8>, TokenError> {
            use rand::RngCore;
            // Generate a random signature for testing
            let mut sig = vec![0u8; 64];
            rand::thread_rng().fill_bytes(&mut sig);
            Ok(sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_token() -> DetectedToken {
        DetectedToken {
            provider: PathBuf::from("/test/provider.so"),
            slot: 0,
            label: "Test Token".to_string(),
            manufacturer: "Test Manufacturer".to_string(),
            serial: "123456".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string(), "CKM_ECDH".to_string()],
        }
    }

    #[test]
    fn test_token_supports_ed25519() {
        let token = test_token();
        assert!(token.supports_ed25519());
    }

    #[test]
    fn test_token_display() {
        let token = test_token();
        let display = format!("{token}");
        assert!(display.contains("Test Token"));
        assert!(display.contains("Test Manufacturer"));
    }

    #[test]
    fn test_detector_creation() {
        let detector = TokenDetector::new();
        assert!(!detector.provider_paths.is_empty());
    }

    #[test]
    fn test_mock_provider() {
        use mock::MockTokenProvider;

        let mut provider = MockTokenProvider::new();
        provider.add_token(test_token());

        let tokens = provider.list_tokens();
        assert_eq!(tokens.len(), 1);

        let pubkey = provider
            .generate_keypair(&tokens[0], "1234", "test-key")
            .unwrap();
        assert_eq!(pubkey.len(), 32);
    }

    // ---- DetectedToken mechanism checks ----

    #[test]
    fn token_without_ed25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        assert!(!token.supports_ed25519());
    }

    #[test]
    fn token_supports_ed25519_via_eddsa() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_EDDSA".to_string()];
        assert!(token.supports_ed25519());
    }

    #[test]
    fn token_supports_x25519_via_ecdh() {
        let token = test_token();
        assert!(token.supports_x25519());
    }

    #[test]
    fn token_without_x25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        assert!(!token.supports_x25519());
    }

    #[test]
    fn token_supports_x25519_via_x25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_X25519".to_string()];
        assert!(token.supports_x25519());
    }

    #[test]
    fn token_empty_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![];
        assert!(!token.supports_ed25519());
        assert!(!token.supports_x25519());
    }

    // ---- DetectedToken Display ----

    #[test]
    fn token_display_format() {
        let token = test_token();
        let display = format!("{token}");
        assert_eq!(display, "Test Token (Test Manufacturer) [slot 0]");
    }

    // ---- DetectedToken serde roundtrip ----

    #[test]
    fn token_serde_roundtrip() {
        let token = test_token();
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
    }

    // ---- TokenDetector ----

    #[test]
    fn detector_default_same_as_new() {
        let d1 = TokenDetector::new();
        let d2 = TokenDetector::default();
        assert_eq!(d1.provider_paths.len(), d2.provider_paths.len());
    }

    #[test]
    fn detector_add_provider() {
        let mut detector = TokenDetector::new();
        let original_count = detector.provider_paths.len();
        detector.add_provider(PathBuf::from("/custom/pkcs11.so"));
        assert_eq!(detector.provider_paths.len(), original_count + 1);
    }

    #[test]
    fn detector_detect_all_returns_empty_in_ci() {
        let detector = TokenDetector::new();
        let tokens = detector.detect_all();
        // No real PKCS#11 providers in CI
        assert!(tokens.is_empty());
    }

    #[test]
    fn detector_detect_fcp_compatible_returns_empty_in_ci() {
        let detector = TokenDetector::new();
        let tokens = detector.detect_fcp_compatible();
        assert!(tokens.is_empty());
    }

    // ---- MockTokenProvider ----

    #[test]
    fn mock_provider_default() {
        use mock::MockTokenProvider;
        let provider = MockTokenProvider::default();
        assert!(provider.list_tokens().is_empty());
    }

    #[test]
    fn mock_provider_sign_returns_64_bytes() {
        use mock::MockTokenProvider;
        let mut provider = MockTokenProvider::new();
        let token = test_token();
        provider.add_token(token.clone());
        let sig = provider.sign(&token, "1234", "test-key", b"data").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn mock_provider_multiple_tokens() {
        use mock::MockTokenProvider;
        let mut provider = MockTokenProvider::new();
        let mut t1 = test_token();
        t1.slot = 0;
        t1.label = "Token A".into();
        let mut t2 = test_token();
        t2.slot = 1;
        t2.label = "Token B".into();
        provider.add_token(t1);
        provider.add_token(t2);
        assert_eq!(provider.list_tokens().len(), 2);
    }

    // ---- TokenError Display ----

    #[test]
    fn token_error_display() {
        assert_eq!(TokenError::NoTokens.to_string(), "no hardware tokens detected");
        assert!(TokenError::TokenNotFound("yubikey".into()).to_string().contains("yubikey"));
        assert_eq!(TokenError::InvalidPin.to_string(), "invalid PIN");
        assert!(TokenError::KeyNotFound("owner".into()).to_string().contains("owner"));
        assert!(TokenError::UnsupportedMechanism("RSA".into()).to_string().contains("RSA"));
        assert!(TokenError::Pkcs11("init failed".into()).to_string().contains("init failed"));
        assert_eq!(TokenError::Disconnected.to_string(), "token disconnected");
    }
}
