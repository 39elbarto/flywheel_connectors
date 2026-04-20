//! Bootstrap error types.

use crate::hardware_token::CertificateSelectionRefusal;
use std::time::Duration;
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

    /// Requested key label was not found on the authenticated token.
    #[error(
        "hardware token key not found: {key} — ensure the token is provisioned with the expected key label"
    )]
    HardwareTokenKeyNotFound {
        /// The missing key label or identifier.
        key: String,
    },

    /// Token authentication succeeded, but no usable identity could be chosen.
    #[error("hardware token certificate selection failed: {refusal}")]
    HardwareTokenCertificateSelectionFailed {
        /// Typed refusal describing why selection could not proceed.
        refusal: CertificateSelectionRefusal,
    },

    /// No hardware tokens found.
    #[error("no hardware tokens detected")]
    NoHardwareTokens,

    /// Hardware token PIN is required for authentication.
    #[error(
        "hardware token PIN is required: provide via --hardware-token-pin or interactive prompt"
    )]
    HardwareTokenPinRequired,

    /// Hardware token PIN was rejected by the token.
    #[error(
        "hardware token PIN was rejected: verify and retry; repeated failures will lock the token"
    )]
    HardwareTokenInvalidPin,

    /// Hardware token PIN is locked after too many failed attempts.
    #[error("hardware token PIN is locked: use the token vendor's management tool to reset it")]
    HardwareTokenPinLocked,

    /// Requested hardware token was not found during discovery.
    #[error(
        "hardware token not found: {locator} — verify token is connected and provider library is installed"
    )]
    HardwareTokenNotFound {
        /// Locator string identifying the requested token.
        locator: String,
    },

    /// Hardware token lacks a required cryptographic mechanism.
    #[error("hardware token does not support {mechanism}: Ed25519 or EdDSA signing is required")]
    HardwareTokenUnsupported {
        /// The missing mechanism description.
        mechanism: String,
    },

    /// Hardware token was disconnected during bootstrap.
    #[error("hardware token disconnected: re-insert the token and retry")]
    HardwareTokenDisconnected,

    /// Hardware token session expired before the operation completed.
    #[error(
        "hardware token session expired after {elapsed:?} (timeout: {timeout:?}): retry or increase --session-timeout"
    )]
    HardwareTokenSessionExpired {
        /// Elapsed time since session was opened.
        elapsed: Duration,
        /// The configured session timeout.
        timeout: Duration,
    },

    /// Hardware token operation was cancelled by the user or the token.
    #[error("hardware token operation was cancelled: retry when ready")]
    HardwareTokenCancelled,

    /// PKCS#11 provider reported an unrecoverable error.
    #[error("hardware token provider fault: {detail} — check provider library and token firmware")]
    HardwareTokenProviderFault {
        /// Error detail from the PKCS#11 layer.
        detail: String,
    },

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
    fn display_hardware_token_key_not_found() {
        let err = BootstrapError::HardwareTokenKeyNotFound {
            key: "owner-key".into(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("owner-key"));
        assert!(rendered.contains("not found"));
    }

    #[test]
    fn display_hardware_token_certificate_selection_failed() {
        let err = BootstrapError::HardwareTokenCertificateSelectionFailed {
            refusal: CertificateSelectionRefusal::NoCertificates,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("certificate selection failed"));
        assert!(rendered.contains("no certificates"));
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
            fingerprint: "BLAKE3:deadbeef".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("AlreadyExists"));
        assert!(debug.contains("BLAKE3:deadbeef"));
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
            expected: "BLAKE3:aaa".into(),
            actual: "BLAKE3:bbb".into(),
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
            expected: "BLAKE3:AAAA".into(),
            actual: "BLAKE3:BBBB".into(),
        };
        let s = err.to_string();
        assert!(s.contains("BLAKE3:AAAA"));
        assert!(s.contains("BLAKE3:BBBB"));
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
        let fp = "BLAKE3:".to_string() + &"A".repeat(200);
        let err = BootstrapError::AlreadyExists {
            fingerprint: fp.clone(),
        };
        assert!(err.to_string().contains(&fp));
    }

    // ---- BootstrapError Debug for all variants ----

    #[test]
    fn debug_no_hardware_tokens() {
        let err = BootstrapError::NoHardwareTokens;
        let debug = format!("{err:?}");
        assert!(debug.contains("NoHardwareTokens"));
    }

    #[test]
    fn debug_serialization() {
        let err = BootstrapError::Serialization("encode fail".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Serialization"));
        assert!(debug.contains("encode fail"));
    }

    #[test]
    fn debug_config() {
        let err = BootstrapError::Config("bad config".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Config"));
    }

    #[test]
    fn debug_internal() {
        let err = BootstrapError::Internal("state machine bug".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Internal"));
    }

    #[test]
    fn debug_crypto() {
        let err = BootstrapError::Crypto("key error".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Crypto"));
    }

    #[test]
    fn debug_hardware_token() {
        let err = BootstrapError::HardwareToken("slot 0 busy".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("HardwareToken"));
        assert!(debug.contains("slot 0 busy"));
    }

    #[test]
    fn debug_io() {
        let io_err = std::io::Error::other("disk full");
        let err = BootstrapError::Io(io_err);
        let debug = format!("{err:?}");
        assert!(debug.contains("Io"));
    }

    #[test]
    fn debug_invalid_recovery_phrase() {
        let err = BootstrapError::InvalidRecoveryPhrase("bad checksum".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidRecoveryPhrase"));
    }

    #[test]
    fn debug_hardware_token_key_not_found() {
        let err = BootstrapError::HardwareTokenKeyNotFound {
            key: "owner-key".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("HardwareTokenKeyNotFound"));
        assert!(debug.contains("owner-key"));
    }

    #[test]
    fn debug_hardware_token_certificate_selection_failed() {
        let err = BootstrapError::HardwareTokenCertificateSelectionFailed {
            refusal: CertificateSelectionRefusal::NoCertificates,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("HardwareTokenCertificateSelectionFailed"));
        assert!(debug.contains("NoCertificates"));
    }

    // ---- Display consistency checks ----

    #[test]
    fn display_time_skew_contains_drift_value() {
        let err = BootstrapError::TimeSkew {
            drift: Duration::from_secs(42),
            suggestion: "fix clock",
        };
        let s = err.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("fix clock"));
    }

    #[test]
    fn display_partial_state_contains_phase() {
        let err = BootstrapError::PartialState {
            phase: "Enrollment".into(),
        };
        assert!(err.to_string().contains("Enrollment"));
    }

    // ---- From io error preserves other kinds ----

    #[test]
    fn from_io_error_preserves_kind_timed_out() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err: BootstrapError = io_err.into();
        match err {
            BootstrapError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn from_io_error_preserves_kind_already_exists() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "exists");
        let err: BootstrapError = io_err.into();
        match err {
            BootstrapError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    // ---- BootstrapResult with unit ----

    #[test]
    fn bootstrap_result_unit_ok() {
        let r: BootstrapResult<()> = Ok(());
        assert!(r.is_ok());
    }

    #[test]
    fn bootstrap_result_unit_err() {
        let r: BootstrapResult<()> = Err(BootstrapError::Internal("fail".into()));
        assert!(r.is_err());
    }

    // ---- Typed hardware-token refusal variants ----

    #[test]
    fn display_hardware_token_pin_required() {
        let err = BootstrapError::HardwareTokenPinRequired;
        let s = err.to_string();
        assert!(s.contains("PIN is required"));
        assert!(s.contains("--hardware-token-pin"));
    }

    #[test]
    fn display_hardware_token_invalid_pin() {
        let err = BootstrapError::HardwareTokenInvalidPin;
        let s = err.to_string();
        assert!(s.contains("PIN was rejected"));
        assert!(s.contains("lock"));
    }

    #[test]
    fn display_hardware_token_pin_locked() {
        let err = BootstrapError::HardwareTokenPinLocked;
        let s = err.to_string();
        assert!(s.contains("PIN is locked"));
        assert!(s.contains("reset"));
    }

    #[test]
    fn display_hardware_token_not_found() {
        let err = BootstrapError::HardwareTokenNotFound {
            locator: "YubiKey [SN001] via /usr/lib/ykcs11.so slot 0".into(),
        };
        let s = err.to_string();
        assert!(s.contains("not found"));
        assert!(s.contains("YubiKey"));
        assert!(s.contains("verify token is connected"));
    }

    #[test]
    fn display_hardware_token_unsupported() {
        let err = BootstrapError::HardwareTokenUnsupported {
            mechanism: "Ed25519 signing".into(),
        };
        let s = err.to_string();
        assert!(s.contains("does not support"));
        assert!(s.contains("Ed25519"));
    }

    #[test]
    fn display_hardware_token_disconnected() {
        let err = BootstrapError::HardwareTokenDisconnected;
        let s = err.to_string();
        assert!(s.contains("disconnected"));
        assert!(s.contains("re-insert"));
    }

    #[test]
    fn display_hardware_token_session_expired() {
        let err = BootstrapError::HardwareTokenSessionExpired {
            elapsed: Duration::from_secs(301),
            timeout: Duration::from_secs(300),
        };
        let s = err.to_string();
        assert!(s.contains("expired"));
        assert!(s.contains("301"));
        assert!(s.contains("--session-timeout"));
    }

    #[test]
    fn display_hardware_token_cancelled() {
        let err = BootstrapError::HardwareTokenCancelled;
        let s = err.to_string();
        assert!(s.contains("cancelled"));
        assert!(s.contains("retry"));
    }

    #[test]
    fn display_hardware_token_provider_fault() {
        let err = BootstrapError::HardwareTokenProviderFault {
            detail: "CKR_DEVICE_ERROR".into(),
        };
        let s = err.to_string();
        assert!(s.contains("provider fault"));
        assert!(s.contains("CKR_DEVICE_ERROR"));
        assert!(s.contains("firmware"));
    }

    // ---- Debug for typed hardware-token refusals ----

    #[test]
    fn debug_hardware_token_pin_required() {
        let err = BootstrapError::HardwareTokenPinRequired;
        let debug = format!("{err:?}");
        assert!(debug.contains("HardwareTokenPinRequired"));
    }

    #[test]
    fn debug_hardware_token_invalid_pin() {
        let err = BootstrapError::HardwareTokenInvalidPin;
        assert!(format!("{err:?}").contains("HardwareTokenInvalidPin"));
    }

    #[test]
    fn debug_hardware_token_pin_locked() {
        let err = BootstrapError::HardwareTokenPinLocked;
        assert!(format!("{err:?}").contains("HardwareTokenPinLocked"));
    }

    #[test]
    fn debug_hardware_token_not_found() {
        let err = BootstrapError::HardwareTokenNotFound {
            locator: "slot-3".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("HardwareTokenNotFound"));
        assert!(debug.contains("slot-3"));
    }

    #[test]
    fn debug_hardware_token_unsupported() {
        let err = BootstrapError::HardwareTokenUnsupported {
            mechanism: "RSA".into(),
        };
        assert!(format!("{err:?}").contains("HardwareTokenUnsupported"));
    }

    #[test]
    fn debug_hardware_token_disconnected() {
        let err = BootstrapError::HardwareTokenDisconnected;
        assert!(format!("{err:?}").contains("HardwareTokenDisconnected"));
    }

    #[test]
    fn debug_hardware_token_session_expired() {
        let err = BootstrapError::HardwareTokenSessionExpired {
            elapsed: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
        };
        assert!(format!("{err:?}").contains("HardwareTokenSessionExpired"));
    }

    #[test]
    fn debug_hardware_token_cancelled() {
        let err = BootstrapError::HardwareTokenCancelled;
        assert!(format!("{err:?}").contains("HardwareTokenCancelled"));
    }

    #[test]
    fn debug_hardware_token_provider_fault() {
        let err = BootstrapError::HardwareTokenProviderFault {
            detail: "init failed".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("HardwareTokenProviderFault"));
        assert!(debug.contains("init failed"));
    }

    // ---- All typed refusal variants have no source ----

    #[test]
    fn hardware_token_refusal_variants_have_no_source() {
        use std::error::Error;
        let variants: Vec<BootstrapError> = vec![
            BootstrapError::HardwareTokenPinRequired,
            BootstrapError::HardwareTokenInvalidPin,
            BootstrapError::HardwareTokenPinLocked,
            BootstrapError::HardwareTokenNotFound {
                locator: "x".into(),
            },
            BootstrapError::HardwareTokenKeyNotFound { key: "x".into() },
            BootstrapError::HardwareTokenCertificateSelectionFailed {
                refusal: CertificateSelectionRefusal::NoCertificates,
            },
            BootstrapError::HardwareTokenUnsupported {
                mechanism: "x".into(),
            },
            BootstrapError::HardwareTokenDisconnected,
            BootstrapError::HardwareTokenSessionExpired {
                elapsed: Duration::from_secs(1),
                timeout: Duration::from_secs(1),
            },
            BootstrapError::HardwareTokenCancelled,
            BootstrapError::HardwareTokenProviderFault { detail: "x".into() },
        ];
        for err in &variants {
            assert!(err.source().is_none(), "expected no source for {err:?}");
        }
    }
}
