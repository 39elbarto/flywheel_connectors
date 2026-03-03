//! Error types for Tailscale integration.

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

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
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
}
