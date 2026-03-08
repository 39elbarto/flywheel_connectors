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

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn timestamp_validation_with_none_timestamp() {
        let e = WebhookError::TimestampValidation {
            reason: "missing".into(),
            timestamp: None,
            current_time: 1000,
            tolerance: Duration::from_secs(300),
        };
        assert_eq!(e.to_string(), "Timestamp validation failed: missing");
    }

    #[test]
    fn error_debug_includes_variant_name() {
        let e = WebhookError::InvalidSignature;
        let debug = format!("{e:?}");
        assert!(debug.contains("InvalidSignature"));

        let e = WebhookError::ReplayDetected {
            event_id: "evt_1".into(),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("ReplayDetected"));
        assert!(debug.contains("evt_1"));
    }

    #[test]
    fn error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(WebhookError::InvalidSignature);
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn payload_too_large_zero_limit() {
        let e = WebhookError::PayloadTooLarge { size: 1, limit: 0 };
        assert_eq!(
            e.to_string(),
            "Payload too large: 1 bytes exceeds limit of 0"
        );
    }

    #[test]
    fn json_error_display_includes_detail() {
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("{invalid}");
        let e: WebhookError = json_err.unwrap_err().into();
        let display = e.to_string();
        assert!(display.starts_with("JSON parsing error:"));
    }

    #[test]
    fn hex_error_display_includes_detail() {
        let hex_err = hex::decode("zz").unwrap_err();
        let e: WebhookError = hex_err.into();
        let display = e.to_string();
        assert!(display.starts_with("Hex decoding error:"));
    }

    // ── Batch 3: SunnyMoose deep test expansion ──

    #[test]
    fn timestamp_validation_zero_tolerance() {
        let e = WebhookError::TimestampValidation {
            reason: "zero tolerance".into(),
            timestamp: Some(100),
            current_time: 100,
            tolerance: Duration::from_secs(0),
        };
        assert_eq!(e.to_string(), "Timestamp validation failed: zero tolerance");
    }

    #[test]
    fn timestamp_validation_large_time_values() {
        let e = WebhookError::TimestampValidation {
            reason: "far future".into(),
            timestamp: Some(i64::MAX),
            current_time: i64::MAX,
            tolerance: Duration::from_secs(u64::MAX),
        };
        let display = e.to_string();
        assert!(display.contains("far future"));
    }

    #[test]
    fn missing_signature_empty_header_name() {
        let e = WebhookError::MissingSignature(String::new());
        assert_eq!(e.to_string(), "Missing signature header: ");
    }

    #[test]
    fn missing_signature_unicode_header_name() {
        let e = WebhookError::MissingSignature("X-Sig-\u{1F512}".into());
        let display = e.to_string();
        assert!(display.contains('\u{1F512}'));
    }

    #[test]
    fn replay_detected_unicode_event_id() {
        let e = WebhookError::ReplayDetected {
            event_id: "evt_\u{00E9}\u{00F1}".into(),
        };
        let display = e.to_string();
        assert!(display.contains("evt_\u{00E9}\u{00F1}"));
    }

    #[test]
    fn invalid_payload_unicode_message() {
        let e = WebhookError::InvalidPayload("l\u{00E4}nge ung\u{00FC}ltig".into());
        let display = e.to_string();
        assert!(display.contains("ung\u{00FC}ltig"));
    }

    #[test]
    fn provider_not_configured_empty() {
        let e = WebhookError::ProviderNotConfigured(String::new());
        assert_eq!(e.to_string(), "Provider not configured: ");
    }

    #[test]
    fn ip_not_allowed_ipv6() {
        let e = WebhookError::IpNotAllowed("::1".into());
        assert_eq!(e.to_string(), "IP address not in allowlist: ::1");
    }

    #[test]
    fn delivery_failed_empty_message() {
        let e = WebhookError::DeliveryFailed(String::new());
        assert_eq!(e.to_string(), "Webhook delivery failed: ");
    }

    #[test]
    fn unsupported_event_type_long_name() {
        let long_type = "a".repeat(1000);
        let e = WebhookError::UnsupportedEventType(long_type.clone());
        let display = e.to_string();
        assert!(display.contains(&long_type));
    }

    #[test]
    fn error_source_json_error() {
        use std::error::Error;
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("{bad}");
        let e: WebhookError = json_err.unwrap_err().into();
        // JsonError variant should have a source
        assert!(e.source().is_some());
    }

    #[test]
    fn error_source_hex_error() {
        use std::error::Error;
        let hex_err = hex::decode("zz").unwrap_err();
        let e: WebhookError = hex_err.into();
        assert!(e.source().is_some());
    }

    #[test]
    fn error_source_none_for_simple_variants() {
        use std::error::Error;
        assert!(WebhookError::InvalidSignature.source().is_none());
        assert!(
            WebhookError::MissingSignature("X".into())
                .source()
                .is_none()
        );
        assert!(WebhookError::InvalidPayload("X".into()).source().is_none());
    }

    #[test]
    fn payload_too_large_max_values() {
        let e = WebhookError::PayloadTooLarge {
            size: usize::MAX,
            limit: usize::MAX - 1,
        };
        let display = e.to_string();
        assert!(display.contains("bytes exceeds limit of"));
    }
}
