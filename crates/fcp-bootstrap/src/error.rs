//! Bootstrap error types.

use thiserror::Error;

/// Result type for bootstrap operations.
pub type BootstrapResult<T> = Result<T, BootstrapError>;

/// Errors that can occur during bootstrap operations.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Time synchronization error.
    #[error("time skew detected: drift={drift:?}, suggestion: {suggestion}")]
    TimeSkew {
        /// Amount of clock drift detected.
        drift: std::time::Duration,
        /// Suggestion for the user.
        suggestion: &'static str,
    },

    /// Genesis already exists at this location.
    #[error("genesis already exists: fingerprint={fingerprint}")]
    AlreadyExists {
        /// Fingerprint of the existing genesis.
        fingerprint: String,
    },

    /// Partial state detected from a crashed initialization.
    #[error("partial bootstrap state detected at phase: {phase}")]
    PartialState {
        /// Phase where the crash occurred.
        phase: String,
    },

    /// Recovery phrase is invalid.
    #[error("invalid recovery phrase: {0}")]
    InvalidRecoveryPhrase(String),

    /// Fingerprint mismatch during recovery.
    #[error("genesis fingerprint mismatch: expected={expected}, actual={actual}")]
    FingerprintMismatch {
        /// Expected fingerprint.
        expected: String,
        /// Actual fingerprint computed.
        actual: String,
    },

    /// Ceremony error.
    #[error("ceremony error: {0}")]
    Ceremony(String),

    /// Ceremony timeout.
    #[error("ceremony timed out at phase: {phase}")]
    CeremonyTimeout {
        /// Phase where the timeout occurred.
        phase: String,
    },

    /// Hardware token error.
    #[error("hardware token error: {0}")]
    HardwareToken(String),

    /// No hardware tokens found.
    #[error("no hardware tokens detected")]
    NoHardwareTokens,

    /// Cryptographic error.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<ciborium::ser::Error<std::io::Error>> for BootstrapError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for BootstrapError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Self::Serialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ---- Display messages ----

    #[test]
    fn display_time_skew() {
        let err = BootstrapError::TimeSkew {
            drift: Duration::from_secs(120),
            suggestion: "sync clock",
        };
        let s = err.to_string();
        assert!(s.contains("time skew"));
        assert!(s.contains("sync clock"));
    }

    #[test]
    fn display_already_exists() {
        let err = BootstrapError::AlreadyExists {
            fingerprint: "abc123".into(),
        };
        assert!(err.to_string().contains("abc123"));
    }

    #[test]
    fn display_partial_state() {
        let err = BootstrapError::PartialState {
            phase: "CeremonyRound1".into(),
        };
        assert!(err.to_string().contains("CeremonyRound1"));
    }

    #[test]
    fn display_invalid_recovery_phrase() {
        let err = BootstrapError::InvalidRecoveryPhrase("bad words".into());
        assert!(err.to_string().contains("bad words"));
    }

    #[test]
    fn display_fingerprint_mismatch() {
        let err = BootstrapError::FingerprintMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        let s = err.to_string();
        assert!(s.contains("aaa"));
        assert!(s.contains("bbb"));
    }

    #[test]
    fn display_ceremony() {
        let err = BootstrapError::Ceremony("round failed".into());
        assert!(err.to_string().contains("round failed"));
    }

    #[test]
    fn display_ceremony_timeout() {
        let err = BootstrapError::CeremonyTimeout {
            phase: "Round2".into(),
        };
        assert!(err.to_string().contains("timed out"));
        assert!(err.to_string().contains("Round2"));
    }

    #[test]
    fn display_hardware_token() {
        let err = BootstrapError::HardwareToken("PKCS#11 init failed".into());
        assert!(err.to_string().contains("PKCS#11"));
    }

    #[test]
    fn display_no_hardware_tokens() {
        let err = BootstrapError::NoHardwareTokens;
        assert!(err.to_string().contains("no hardware tokens"));
    }

    #[test]
    fn display_crypto() {
        let err = BootstrapError::Crypto("key derivation failed".into());
        assert!(err.to_string().contains("key derivation"));
    }

    #[test]
    fn display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = BootstrapError::Io(io_err);
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn display_serialization() {
        let err = BootstrapError::Serialization("CBOR decode error".into());
        assert!(err.to_string().contains("CBOR decode"));
    }

    #[test]
    fn display_config() {
        let err = BootstrapError::Config("data_dir required".into());
        assert!(err.to_string().contains("data_dir required"));
    }

    #[test]
    fn display_internal() {
        let err = BootstrapError::Internal("unexpected state".into());
        assert!(err.to_string().contains("unexpected state"));
    }

    // ---- From impls ----

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: BootstrapError = io_err.into();
        match err {
            BootstrapError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    // ---- std::error::Error impl ----

    #[test]
    fn error_trait_impl() {
        let err = BootstrapError::Config("test".into());
        let _: &dyn std::error::Error = &err;
    }

    // ---- BootstrapResult type alias ----

    #[test]
    fn bootstrap_result_ok() {
        let r: BootstrapResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn bootstrap_result_err() {
        let r: BootstrapResult<u32> = Err(BootstrapError::NoHardwareTokens);
        assert!(r.is_err());
    }
}
