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

    // ---- Debug formatting ----

    #[test]
    fn debug_time_skew() {
        let err = BootstrapError::TimeSkew {
            drift: Duration::from_secs(300),
            suggestion: "sync your clock",
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("TimeSkew"));
        assert!(debug.contains("sync your clock"));
    }

    #[test]
    fn debug_already_exists() {
        let err = BootstrapError::AlreadyExists {
            fingerprint: "SHA256:deadbeef".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("AlreadyExists"));
        assert!(debug.contains("SHA256:deadbeef"));
    }

    #[test]
    fn debug_partial_state() {
        let err = BootstrapError::PartialState {
            phase: "GenesisCreate".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("PartialState"));
        assert!(debug.contains("GenesisCreate"));
    }

    #[test]
    fn debug_fingerprint_mismatch() {
        let err = BootstrapError::FingerprintMismatch {
            expected: "SHA256:aaa".into(),
            actual: "SHA256:bbb".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("FingerprintMismatch"));
    }

    #[test]
    fn debug_ceremony_timeout() {
        let err = BootstrapError::CeremonyTimeout {
            phase: "Round1".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("CeremonyTimeout"));
        assert!(debug.contains("Round1"));
    }

    // ---- Display with empty/special strings ----

    #[test]
    fn display_ceremony_empty_message() {
        let err = BootstrapError::Ceremony(String::new());
        let s = err.to_string();
        assert!(s.contains("ceremony error"));
    }

    #[test]
    fn display_crypto_unicode_message() {
        let err = BootstrapError::Crypto("cl\u{00e9} invalide".into());
        let s = err.to_string();
        assert!(s.contains("cl\u{00e9}"));
    }

    #[test]
    fn display_config_empty_message() {
        let err = BootstrapError::Config(String::new());
        let s = err.to_string();
        assert!(s.contains("configuration error"));
    }

    #[test]
    fn display_internal_long_message() {
        let msg = "x".repeat(1000);
        let err = BootstrapError::Internal(msg.clone());
        assert!(err.to_string().contains(&msg));
    }

    #[test]
    fn from_io_error_preserves_kind_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: BootstrapError = io_err.into();
        match err {
            BootstrapError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    // ---- Source chain ----

    #[test]
    fn io_error_source_chain() {
        use std::error::Error;
        let io_err = std::io::Error::other("inner");
        let err = BootstrapError::Io(io_err);
        // The #[from] attribute sets up the source chain
        assert!(err.source().is_some());
    }

    #[test]
    fn ceremony_error_has_no_source() {
        use std::error::Error;
        let err = BootstrapError::Ceremony("test".into());
        assert!(err.source().is_none());
    }

    #[test]
    fn no_hardware_tokens_has_no_source() {
        use std::error::Error;
        let err = BootstrapError::NoHardwareTokens;
        assert!(err.source().is_none());
    }

    // ---- Debug vs Display difference ----

    #[test]
    fn debug_and_display_differ_for_time_skew() {
        let err = BootstrapError::TimeSkew {
            drift: Duration::from_secs(60),
            suggestion: "run ntpd",
        };
        let display = format!("{err}");
        let debug = format!("{err:?}");
        // Debug includes variant name, Display does not
        assert!(debug.contains("TimeSkew"));
        assert!(!display.contains("TimeSkew"));
        // Both include the message content
        assert!(display.contains("run ntpd"));
        assert!(debug.contains("run ntpd"));
    }

    // ---- Error message content ----

    #[test]
    fn fingerprint_mismatch_contains_both_values() {
        let err = BootstrapError::FingerprintMismatch {
            expected: "SHA256:AAAA".into(),
            actual: "SHA256:BBBB".into(),
        };
        let s = err.to_string();
        assert!(s.contains("SHA256:AAAA"));
        assert!(s.contains("SHA256:BBBB"));
        assert!(s.contains("mismatch"));
    }

    #[test]
    fn ceremony_timeout_includes_phase() {
        let err = BootstrapError::CeremonyTimeout {
            phase: "CeremonyRound2".into(),
        };
        let s = err.to_string();
        assert!(s.contains("timed out"));
        assert!(s.contains("CeremonyRound2"));
    }

    // ---- BootstrapResult with complex types ----

    #[test]
    fn bootstrap_result_with_vec() {
        let v = vec![1_u8, 2, 3];
        let r: BootstrapResult<Vec<u8>> = Ok(v);
        match r {
            Ok(inner) => assert_eq!(inner.len(), 3),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn bootstrap_result_with_string() {
        let r: BootstrapResult<String> = Err(BootstrapError::Internal("oops".into()));
        assert!(r.is_err());
    }

    // ---- From impls for ciborium errors ----

    #[test]
    fn from_ciborium_ser_error() {
        // Construct a ciborium ser error via serialization of an unserializable value
        let io_err = std::io::Error::other("write fail");
        let cbor_err = ciborium::ser::Error::Io(io_err);
        let err: BootstrapError = cbor_err.into();
        match err {
            BootstrapError::Serialization(msg) => assert!(!msg.is_empty()),
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn from_ciborium_de_error() {
        // Construct by trying to deserialize invalid data
        let result: Result<u32, _> = ciborium::from_reader::<u32, _>(&[0xFF][..]);
        if let Err(cbor_err) = result {
            let err: BootstrapError = cbor_err.into();
            match err {
                BootstrapError::Serialization(msg) => assert!(!msg.is_empty()),
                other => panic!("expected Serialization, got {other:?}"),
            }
        }
    }

    // ---- Large field values ----

    #[test]
    fn time_skew_with_very_large_drift() {
        let err = BootstrapError::TimeSkew {
            drift: Duration::from_secs(86400 * 365),
            suggestion: "check hardware clock",
        };
        let s = err.to_string();
        assert!(s.contains("check hardware clock"));
    }

    #[test]
    fn already_exists_with_long_fingerprint() {
        let fp = "SHA256:".to_string() + &"A".repeat(200);
        let err = BootstrapError::AlreadyExists {
            fingerprint: fp.clone(),
        };
        assert!(err.to_string().contains(&fp));
    }
}
