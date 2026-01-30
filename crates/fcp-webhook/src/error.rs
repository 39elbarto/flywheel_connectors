//! Webhook error types.

use std::time::Duration;

/// Webhook errors.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// Invalid signature.
    #[error("Invalid webhook signature")]
    InvalidSignature,

    /// Missing signature header.
    #[error("Missing signature header: {0}")]
    MissingSignature(String),

    /// Timestamp validation failed.
    #[error("Timestamp validation failed: {reason}")]
    TimestampValidation {
        /// Failure reason.
        reason: String,
        /// Actual timestamp.
        timestamp: Option<i64>,
        /// Current time.
        current_time: i64,
        /// Allowed tolerance.
        tolerance: Duration,
    },

    /// Replay detected (duplicate event).
    #[error("Replay detected: event {event_id} already processed")]
    ReplayDetected {
        /// Duplicate event ID.
        event_id: String,
    },

    /// Payload too large.
    #[error("Payload too large: {size} bytes exceeds limit of {limit}")]
    PayloadTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// Invalid payload format.
    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    /// Unsupported event type.
    #[error("Unsupported event type: {0}")]
    UnsupportedEventType(String),

    /// Provider not configured.
    #[error("Provider not configured: {0}")]
    ProviderNotConfigured(String),

    /// IP not allowed.
    #[error("IP address not in allowlist: {0}")]
    IpNotAllowed(String),

    /// Delivery failed.
    #[error("Webhook delivery failed: {0}")]
    DeliveryFailed(String),

    /// JSON parsing error.
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Hex decoding error.
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
}

/// Result type for webhook operations.
pub type WebhookResult<T> = Result<T, WebhookError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_signature_display() {
        let e = WebhookError::InvalidSignature;
        assert_eq!(e.to_string(), "Invalid webhook signature");
    }

    #[test]
    fn missing_signature_display() {
        let e = WebhookError::MissingSignature("X-Hub-Signature-256".into());
        assert_eq!(
            e.to_string(),
            "Missing signature header: X-Hub-Signature-256"
        );
    }

    #[test]
    fn timestamp_validation_display() {
        let e = WebhookError::TimestampValidation {
            reason: "too old".into(),
            timestamp: Some(1000),
            current_time: 2000,
            tolerance: Duration::from_secs(300),
        };
        assert_eq!(e.to_string(), "Timestamp validation failed: too old");
    }

    #[test]
    fn replay_detected_display() {
        let e = WebhookError::ReplayDetected {
            event_id: "evt_123".into(),
        };
        assert_eq!(
            e.to_string(),
            "Replay detected: event evt_123 already processed"
        );
    }

    #[test]
    fn payload_too_large_display() {
        let e = WebhookError::PayloadTooLarge {
            size: 10_000_000,
            limit: 5_000_000,
        };
        assert_eq!(
            e.to_string(),
            "Payload too large: 10000000 bytes exceeds limit of 5000000"
        );
    }

    #[test]
    fn invalid_payload_display() {
        let e = WebhookError::InvalidPayload("bad format".into());
        assert_eq!(e.to_string(), "Invalid payload: bad format");
    }

    #[test]
    fn unsupported_event_type_display() {
        let e = WebhookError::UnsupportedEventType("unknown".into());
        assert_eq!(e.to_string(), "Unsupported event type: unknown");
    }

    #[test]
    fn provider_not_configured_display() {
        let e = WebhookError::ProviderNotConfigured("custom".into());
        assert_eq!(e.to_string(), "Provider not configured: custom");
    }

    #[test]
    fn ip_not_allowed_display() {
        let e = WebhookError::IpNotAllowed("10.0.0.1".into());
        assert_eq!(e.to_string(), "IP address not in allowlist: 10.0.0.1");
    }

    #[test]
    fn delivery_failed_display() {
        let e = WebhookError::DeliveryFailed("timeout".into());
        assert_eq!(e.to_string(), "Webhook delivery failed: timeout");
    }

    #[test]
    fn json_error_from() {
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("not json");
        let e: WebhookError = json_err.unwrap_err().into();
        assert!(matches!(e, WebhookError::JsonError(_)));
    }

    #[test]
    fn hex_error_from() {
        let hex_err = hex::decode("not-hex").unwrap_err();
        let e: WebhookError = hex_err.into();
        assert!(matches!(e, WebhookError::HexError(_)));
    }
}
