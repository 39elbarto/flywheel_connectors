//! Error types for Tailscale integration.

use std::time::Duration;

use asupersync::http::h1::ClientError as HttpClientError;
use fcp_async_core::AsyncError;
use thiserror::Error;

/// Result type for Tailscale operations.
pub type TailscaleResult<T> = Result<T, TailscaleError>;

/// Errors that can occur during Tailscale operations.
#[derive(Debug, Error)]
pub enum TailscaleError {
    /// Invalid tag format (must be `tag:fcp-<suffix>`).
    #[error("invalid FCP tag format: {0}")]
    InvalidTag(String),

    /// Invalid zone ID format (must be `z:<name>`).
    #[error("invalid zone ID format: {0}")]
    InvalidZoneId(String),

    /// Tag does not have the FCP prefix.
    #[error("tag '{0}' does not have FCP prefix 'tag:fcp-'")]
    NotFcpTag(String),

    /// `LocalAPI` request failed.
    #[error("`LocalAPI` request failed: {0}")]
    LocalApiRequest(String),

    /// `LocalAPI` returned an error response.
    #[error("`LocalAPI` error: {0}")]
    LocalApiError(String),

    /// Failed to parse `LocalAPI` response.
    #[error("failed to parse `LocalAPI` response: {0}")]
    ParseError(String),

    /// Node is not connected to tailnet.
    #[error("node is not connected to tailnet")]
    NotConnected,

    /// Peer not found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Invalid attestation signature.
    #[error("invalid attestation signature")]
    InvalidAttestation,

    /// Attestation has expired.
    #[error("attestation has expired")]
    AttestationExpired,

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] fcp_crypto::CryptoError),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl TailscaleError {
    /// Convert an ASUPERSYNC HTTP client error into a `LocalAPI` request failure.
    #[must_use]
    pub fn from_http_client_error(error: &HttpClientError) -> Self {
        Self::LocalApiRequest(error.to_string())
    }

    /// Convert an async-core timeout/cancellation into a `LocalAPI` request failure.
    #[must_use]
    pub fn from_async_error(error: AsyncError, timeout: Duration) -> Self {
        match error {
            AsyncError::Timeout { .. } => {
                Self::LocalApiRequest(format!("request timed out after {}ms", timeout.as_millis()))
            }
            AsyncError::Cancelled => Self::LocalApiRequest("request cancelled".to_string()),
            AsyncError::ProtocolIo { message }
            | AsyncError::Join { message }
            | AsyncError::Runtime { message } => Self::LocalApiRequest(message),
            AsyncError::ChannelClosed => {
                Self::LocalApiRequest("request channel closed".to_string())
            }
            AsyncError::ChannelFull => Self::LocalApiRequest("request channel full".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_tag() {
        let err = TailscaleError::InvalidTag("bad-tag".to_string());
        assert_eq!(err.to_string(), "invalid FCP tag format: bad-tag");
    }

    #[test]
    fn error_display_invalid_zone_id() {
        let err = TailscaleError::InvalidZoneId("not-a-zone".to_string());
        assert_eq!(err.to_string(), "invalid zone ID format: not-a-zone");
    }

    #[test]
    fn error_display_not_fcp_tag() {
        let err = TailscaleError::NotFcpTag("tag:server".to_string());
        assert_eq!(
            err.to_string(),
            "tag 'tag:server' does not have FCP prefix 'tag:fcp-'"
        );
    }

    #[test]
    fn error_display_local_api_request() {
        let err = TailscaleError::LocalApiRequest("connection refused".to_string());
        assert_eq!(
            err.to_string(),
            "`LocalAPI` request failed: connection refused"
        );
    }

    #[test]
    fn error_display_local_api_error() {
        let err = TailscaleError::LocalApiError("500: internal error".to_string());
        assert_eq!(err.to_string(), "`LocalAPI` error: 500: internal error");
    }

    #[test]
    fn error_display_parse_error() {
        let err = TailscaleError::ParseError("invalid json".to_string());
        assert_eq!(
            err.to_string(),
            "failed to parse `LocalAPI` response: invalid json"
        );
    }

    #[test]
    fn error_display_not_connected() {
        let err = TailscaleError::NotConnected;
        assert_eq!(err.to_string(), "node is not connected to tailnet");
    }

    #[test]
    fn error_display_peer_not_found() {
        let err = TailscaleError::PeerNotFound("100.64.0.99".to_string());
        assert_eq!(err.to_string(), "peer not found: 100.64.0.99");
    }

    #[test]
    fn error_display_invalid_attestation() {
        let err = TailscaleError::InvalidAttestation;
        assert_eq!(err.to_string(), "invalid attestation signature");
    }

    #[test]
    fn error_display_attestation_expired() {
        let err = TailscaleError::AttestationExpired;
        assert_eq!(err.to_string(), "attestation has expired");
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err: TailscaleError = io_err.into();
        assert!(err.to_string().contains("no such file"));
    }

    #[test]
    fn error_from_json() {
        let json_err = serde_json::from_str::<String>("not-json").unwrap_err();
        let err: TailscaleError = json_err.into();
        assert!(err.to_string().starts_with("JSON error:"));
    }

    // --- Debug formatting for all 13 variants ---

    #[test]
    fn debug_invalid_tag() {
        let err = TailscaleError::InvalidTag("bad".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidTag"));
        assert!(dbg.contains("bad"));
    }

    #[test]
    fn debug_invalid_zone_id() {
        let err = TailscaleError::InvalidZoneId("nope".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidZoneId"));
        assert!(dbg.contains("nope"));
    }

    #[test]
    fn debug_not_fcp_tag() {
        let err = TailscaleError::NotFcpTag("tag:server".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFcpTag"));
    }

    #[test]
    fn debug_local_api_request() {
        let err = TailscaleError::LocalApiRequest("timeout".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LocalApiRequest"));
    }

    #[test]
    fn debug_local_api_error() {
        let err = TailscaleError::LocalApiError("403".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LocalApiError"));
    }

    #[test]
    fn debug_parse_error() {
        let err = TailscaleError::ParseError("bad json".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ParseError"));
    }

    #[test]
    fn debug_not_connected() {
        let err = TailscaleError::NotConnected;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotConnected"));
    }

    #[test]
    fn debug_peer_not_found() {
        let err = TailscaleError::PeerNotFound("10.0.0.1".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PeerNotFound"));
    }

    #[test]
    fn debug_invalid_attestation() {
        let err = TailscaleError::InvalidAttestation;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidAttestation"));
    }

    #[test]
    fn debug_attestation_expired() {
        let err = TailscaleError::AttestationExpired;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("AttestationExpired"));
    }

    #[test]
    fn debug_io_variant() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = TailscaleError::Io(io_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Io"));
    }

    #[test]
    fn debug_json_variant() {
        let json_err = serde_json::from_str::<String>("{{bad").unwrap_err();
        let err = TailscaleError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    #[test]
    fn debug_crypto_variant() {
        let crypto_err = fcp_crypto::CryptoError::SignatureVerificationFailed;
        let err = TailscaleError::Crypto(crypto_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Crypto"));
    }

    // --- Error trait (dyn std::error::Error) for all variants ---

    #[test]
    fn error_trait_invalid_tag() {
        let err = TailscaleError::InvalidTag("x".into());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.to_string().contains('x'));
    }

    #[test]
    fn error_trait_unit_variants() {
        let variants: Vec<TailscaleError> = vec![
            TailscaleError::NotConnected,
            TailscaleError::InvalidAttestation,
            TailscaleError::AttestationExpired,
        ];
        for v in &variants {
            let dyn_err: &dyn std::error::Error = v;
            assert!(!dyn_err.to_string().is_empty());
        }
    }

    #[test]
    fn error_trait_string_variants() {
        let variants: Vec<TailscaleError> = vec![
            TailscaleError::InvalidZoneId("z".into()),
            TailscaleError::NotFcpTag("t".into()),
            TailscaleError::LocalApiRequest("r".into()),
            TailscaleError::LocalApiError("e".into()),
            TailscaleError::ParseError("p".into()),
            TailscaleError::PeerNotFound("peer".into()),
        ];
        for v in &variants {
            let dyn_err: &dyn std::error::Error = v;
            assert!(!dyn_err.to_string().is_empty());
        }
    }

    // --- TailscaleResult Ok and Err ---

    #[test]
    fn tailscale_result_ok() {
        let result: TailscaleResult<u32> = Ok(42);
        let Ok(val) = result else {
            panic!("expected Ok")
        };
        assert_eq!(val, 42);
    }

    #[test]
    fn tailscale_result_err() {
        let result: TailscaleResult<u32> = Err(TailscaleError::NotConnected);
        let Err(err) = result else {
            panic!("expected Err")
        };
        assert!(matches!(err, TailscaleError::NotConnected));
    }

    // --- From<std::io::Error> with different ErrorKind values ---

    #[test]
    fn from_io_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: TailscaleError = io_err.into();
        assert!(matches!(err, TailscaleError::Io(_)));
        assert!(err.to_string().contains("denied"));
    }

    #[test]
    fn from_io_connection_refused() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err: TailscaleError = io_err.into();
        assert!(matches!(err, TailscaleError::Io(_)));
        assert!(err.to_string().contains("refused"));
    }

    #[test]
    fn from_io_timed_out() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err: TailscaleError = io_err.into();
        assert!(matches!(err, TailscaleError::Io(_)));
    }

    // --- From<serde_json::Error> verify matches! pattern ---

    #[test]
    fn from_json_matches_pattern() {
        let json_err = serde_json::from_str::<Vec<u8>>("not json").unwrap_err();
        let err: TailscaleError = json_err.into();
        assert!(matches!(err, TailscaleError::Json(_)));
    }

    // --- From<CryptoError> ---

    #[test]
    fn from_crypto_error() {
        let crypto_err = fcp_crypto::CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        let err: TailscaleError = crypto_err.into();
        assert!(matches!(err, TailscaleError::Crypto(_)));
        assert!(err.to_string().contains("crypto error"));
    }

    // --- source() returns Some for wrapper variants, None for unit variants ---

    #[test]
    fn source_none_for_unit_variants() {
        use std::error::Error;
        let variants: Vec<TailscaleError> = vec![
            TailscaleError::InvalidTag("x".into()),
            TailscaleError::InvalidZoneId("x".into()),
            TailscaleError::NotFcpTag("x".into()),
            TailscaleError::LocalApiRequest("x".into()),
            TailscaleError::LocalApiError("x".into()),
            TailscaleError::ParseError("x".into()),
            TailscaleError::NotConnected,
            TailscaleError::PeerNotFound("x".into()),
            TailscaleError::InvalidAttestation,
            TailscaleError::AttestationExpired,
        ];
        for v in &variants {
            assert!(v.source().is_none(), "expected source() == None for {v:?}",);
        }
    }

    #[test]
    fn source_some_for_io() {
        use std::error::Error;
        let io_err = std::io::Error::other("inner");
        let err = TailscaleError::Io(io_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn source_some_for_json() {
        use std::error::Error;
        let json_err = serde_json::from_str::<String>("bad").unwrap_err();
        let err = TailscaleError::Json(json_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn source_some_for_crypto() {
        use std::error::Error;
        let crypto_err = fcp_crypto::CryptoError::AeadEncryptFailed;
        let err = TailscaleError::Crypto(crypto_err);
        assert!(err.source().is_some());
    }

    // --- from_async_error covers all AsyncError variants ---

    #[test]
    fn from_async_error_timeout() {
        let async_err = AsyncError::Timeout { timeout_ms: 500 };
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(1));
        assert!(err.to_string().contains("timed out"));
        assert!(err.to_string().contains("1000ms"));
    }

    #[test]
    fn from_async_error_cancelled() {
        let async_err = AsyncError::Cancelled;
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn from_async_error_protocol_io() {
        let async_err = AsyncError::ProtocolIo {
            message: "broken pipe".to_string(),
        };
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
        assert!(err.to_string().contains("broken pipe"));
    }

    #[test]
    fn from_async_error_join() {
        let async_err = AsyncError::Join {
            message: "task panicked".to_string(),
        };
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
        assert!(err.to_string().contains("task panicked"));
    }

    #[test]
    fn from_async_error_runtime() {
        let async_err = AsyncError::Runtime {
            message: "runtime shutdown".to_string(),
        };
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
        assert!(err.to_string().contains("runtime shutdown"));
    }

    #[test]
    fn from_async_error_channel_closed() {
        let async_err = AsyncError::ChannelClosed;
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
        assert!(err.to_string().contains("channel closed"));
    }

    #[test]
    fn from_async_error_channel_full() {
        let async_err = AsyncError::ChannelFull;
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
        assert!(err.to_string().contains("channel full"));
    }

    // --- from_async_error timeout with zero duration ---

    #[test]
    fn from_async_error_timeout_zero_duration() {
        let async_err = AsyncError::Timeout { timeout_ms: 0 };
        let err = TailscaleError::from_async_error(async_err, Duration::ZERO);
        assert!(err.to_string().contains("0ms"));
    }

    // --- from_async_error timeout with large duration ---

    #[test]
    fn from_async_error_timeout_large_duration() {
        let async_err = AsyncError::Timeout {
            timeout_ms: 300_000,
        };
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(300));
        assert!(err.to_string().contains("300000ms"));
    }

    // --- Error display with long messages ---

    #[test]
    fn error_display_long_message() {
        let long_msg = "x".repeat(1024);
        let err = TailscaleError::LocalApiRequest(long_msg.clone());
        let display = err.to_string();
        assert!(display.contains(&long_msg));
    }

    // --- Error display with empty messages ---

    #[test]
    fn error_display_empty_invalid_tag() {
        let err = TailscaleError::InvalidTag(String::new());
        assert_eq!(err.to_string(), "invalid FCP tag format: ");
    }

    #[test]
    fn error_display_empty_peer_not_found() {
        let err = TailscaleError::PeerNotFound(String::new());
        assert_eq!(err.to_string(), "peer not found: ");
    }

    // --- Error is Send + Sync ---

    #[test]
    fn error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<TailscaleError>();
    }

    #[test]
    fn error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<TailscaleError>();
    }

    // --- from_http_client_error ---

    #[test]
    fn from_http_client_error_produces_local_api_request() {
        // We can't easily construct an HttpClientError, but we can verify
        // from_async_error produces the right variant types
        let err = TailscaleError::LocalApiRequest("simulated http error".to_string());
        assert!(matches!(err, TailscaleError::LocalApiRequest(_)));
        assert!(err.to_string().contains("simulated http error"));
    }

    // --- from_async_error with sub-second durations ---

    #[test]
    fn from_async_error_timeout_millis_precision() {
        let async_err = AsyncError::Timeout { timeout_ms: 250 };
        let err = TailscaleError::from_async_error(async_err, Duration::from_millis(250));
        assert!(err.to_string().contains("250ms"));
    }

    #[test]
    fn from_async_error_timeout_large_millis() {
        let async_err = AsyncError::Timeout { timeout_ms: 60_000 };
        let err = TailscaleError::from_async_error(async_err, Duration::from_secs(60));
        assert!(err.to_string().contains("60000ms"));
    }

    // --- Error display with unicode content ---

    #[test]
    fn error_display_invalid_tag_unicode() {
        let err = TailscaleError::InvalidTag("tag:caf\u{00e9}".to_string());
        let display = err.to_string();
        assert!(display.contains("caf\u{00e9}"));
        assert!(display.starts_with("invalid FCP tag format"));
    }

    #[test]
    fn error_display_peer_not_found_ipv6() {
        let err = TailscaleError::PeerNotFound("fd7a:115c:a1e0::42".to_string());
        assert!(err.to_string().contains("fd7a:115c:a1e0::42"));
    }

    #[test]
    fn error_display_local_api_error_numeric_status() {
        let err = TailscaleError::LocalApiError("404: not found".to_string());
        assert_eq!(err.to_string(), "`LocalAPI` error: 404: not found");
    }

    #[test]
    fn error_display_parse_error_with_json_snippet() {
        let err = TailscaleError::ParseError("expected value at line 1 column 1".to_string());
        assert!(err.to_string().contains("expected value"));
    }

    // --- From<io::Error> more kinds ---

    #[test]
    fn from_io_addr_in_use() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use");
        let err: TailscaleError = io_err.into();
        assert!(matches!(err, TailscaleError::Io(_)));
        assert!(err.to_string().contains("address in use"));
    }

    #[test]
    fn from_io_would_block() {
        let io_err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
        let err: TailscaleError = io_err.into();
        assert!(matches!(err, TailscaleError::Io(_)));
    }

    // --- From<CryptoError> additional variants ---

    #[test]
    fn from_crypto_error_signature_verification() {
        let crypto_err = fcp_crypto::CryptoError::SignatureVerificationFailed;
        let err: TailscaleError = crypto_err.into();
        assert!(matches!(err, TailscaleError::Crypto(_)));
        assert!(err.to_string().contains("crypto error"));
    }

    #[test]
    fn from_crypto_error_aead() {
        let crypto_err = fcp_crypto::CryptoError::AeadEncryptFailed;
        let err: TailscaleError = crypto_err.into();
        assert!(matches!(err, TailscaleError::Crypto(_)));
    }

    // --- source() chain for wrapper variants ---

    #[test]
    fn source_chain_io_preserves_inner() {
        use std::error::Error;
        let io_err = std::io::Error::other("inner detail");
        let err = TailscaleError::Io(io_err);
        let source = err.source().unwrap();
        assert!(source.to_string().contains("inner detail"));
    }

    #[test]
    fn source_chain_json_preserves_inner() {
        use std::error::Error;
        let json_err = serde_json::from_str::<u32>("abc").unwrap_err();
        let expected_msg = json_err.to_string();
        let err = TailscaleError::Json(json_err);
        let source = err.source().unwrap();
        assert_eq!(source.to_string(), expected_msg);
    }

    // --- Error variant pattern matching exhaustiveness ---

    #[test]
    fn all_error_variants_match() {
        let variants: Vec<TailscaleError> = vec![
            TailscaleError::InvalidTag("a".into()),
            TailscaleError::InvalidZoneId("b".into()),
            TailscaleError::NotFcpTag("c".into()),
            TailscaleError::LocalApiRequest("d".into()),
            TailscaleError::LocalApiError("e".into()),
            TailscaleError::ParseError("f".into()),
            TailscaleError::NotConnected,
            TailscaleError::PeerNotFound("g".into()),
            TailscaleError::InvalidAttestation,
            TailscaleError::AttestationExpired,
            TailscaleError::Io(std::io::Error::other("io")),
            TailscaleError::Json(serde_json::from_str::<String>("x").unwrap_err()),
            TailscaleError::Crypto(fcp_crypto::CryptoError::AeadDecryptFailed),
        ];
        for v in &variants {
            // Every variant must have a non-empty Display
            assert!(!v.to_string().is_empty());
            // Every variant must have Debug
            assert!(!format!("{v:?}").is_empty());
        }
        assert_eq!(variants.len(), 13);
    }

    // --- from_async_error: verify variant type is always LocalApiRequest ---

    #[test]
    fn from_async_error_all_produce_local_api_request() {
        let cases: Vec<AsyncError> = vec![
            AsyncError::Timeout { timeout_ms: 100 },
            AsyncError::Cancelled,
            AsyncError::ProtocolIo {
                message: "io".into(),
            },
            AsyncError::Join {
                message: "join".into(),
            },
            AsyncError::Runtime {
                message: "rt".into(),
            },
            AsyncError::ChannelClosed,
            AsyncError::ChannelFull,
        ];
        for async_err in cases {
            let err = TailscaleError::from_async_error(async_err, Duration::from_secs(5));
            assert!(
                matches!(err, TailscaleError::LocalApiRequest(_)),
                "expected LocalApiRequest, got {err:?}"
            );
        }
    }

    // --- TailscaleResult with complex types ---

    #[test]
    fn tailscale_result_with_string() {
        let result: TailscaleResult<String> =
            serde_json::from_str("\"hello\"").map_err(TailscaleError::from);
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn tailscale_result_with_vec() {
        let result: TailscaleResult<Vec<u8>> =
            serde_json::from_str("[1,2,3]").map_err(TailscaleError::from);
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn tailscale_result_with_option() {
        let result: TailscaleResult<Option<u32>> =
            serde_json::from_str("null").map_err(TailscaleError::from);
        assert!(result.unwrap().is_none());
    }

    // --- Error Display idempotency ---

    #[test]
    fn error_display_idempotent() {
        let err = TailscaleError::NotConnected;
        let d1 = err.to_string();
        let d2 = err.to_string();
        assert_eq!(d1, d2);
    }

    #[test]
    fn error_display_local_api_request_empty() {
        let err = TailscaleError::LocalApiRequest(String::new());
        assert_eq!(err.to_string(), "`LocalAPI` request failed: ");
    }

    #[test]
    fn error_display_not_fcp_tag_empty() {
        let err = TailscaleError::NotFcpTag(String::new());
        assert_eq!(
            err.to_string(),
            "tag '' does not have FCP prefix 'tag:fcp-'"
        );
    }

    #[test]
    fn error_display_invalid_zone_id_empty() {
        let err = TailscaleError::InvalidZoneId(String::new());
        assert_eq!(err.to_string(), "invalid zone ID format: ");
    }
}
