//! Webhook error types.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::signature::SignatureAlgorithm;

/// HTTP status used by the host when connector budgets are exhausted.
pub const HOST_BACKPRESSURE_STATUS: u16 = 503;
/// Header carrying host backpressure reason for connector clients.
pub const FCP_BACKPRESSURE_REASON_HEADER: &str = "X-FCP-Backpressure-Reason";
/// Header carrying the host-computed retry floor in whole seconds.
pub const FCP_BACKPRESSURE_RETRY_AFTER_HEADER: &str = "X-FCP-Backpressure-Retry-After";
/// Canonical host backpressure reason for exhausted zone budgets.
pub const FCP_BACKPRESSURE_BUDGET_EXHAUSTED: &str = "budget-exhausted";

/// Host-supplied backpressure signal for webhook retry loops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBackpressureSignal {
    /// Machine-readable reason supplied by the host.
    pub reason: String,
    /// Optional retry floor supplied by `Retry-After` or FCP backpressure headers.
    pub retry_after: Option<Duration>,
}

impl HostBackpressureSignal {
    /// Create a host backpressure signal.
    #[must_use]
    pub fn new(reason: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self {
            reason: reason.into(),
            retry_after,
        }
    }

    /// Return whether connector retry loops should back off.
    #[must_use]
    pub const fn should_back_off(&self) -> bool {
        true
    }

    /// Return the host-supplied retry floor.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Return true for canonical budget-exhaustion backpressure.
    #[must_use]
    pub fn is_budget_exhausted(&self) -> bool {
        self.reason
            .trim()
            .eq_ignore_ascii_case(FCP_BACKPRESSURE_BUDGET_EXHAUSTED)
    }
}

/// Retry decision for webhook deliveries after a host response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookRetryDecision {
    /// Retry after the supplied delay.
    RetryAfter(Duration),
    /// Refuse retry because the host signaled terminal backpressure.
    RefuseRetry(HostBackpressureSignal),
}

fn header_value_case_insensitive<'a, S: BuildHasher>(
    headers: &'a HashMap<String, String, S>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        return Some(Duration::from_secs(
            u64::try_from(seconds).unwrap_or(u64::MAX),
        ));
    }

    let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        wait.to_std().ok().or(Some(Duration::from_secs(u64::MAX)))
    }
}

fn max_retry_after(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Extract host backpressure metadata from a response status and headers.
#[must_use]
pub fn host_backpressure_signal_from_response<S: BuildHasher>(
    status: u16,
    headers: &HashMap<String, String, S>,
) -> Option<HostBackpressureSignal> {
    if status != HOST_BACKPRESSURE_STATUS {
        return None;
    }

    let reason = header_value_case_insensitive(headers, FCP_BACKPRESSURE_REASON_HEADER)?;
    let retry_after = max_retry_after(
        header_value_case_insensitive(headers, "retry-after").and_then(parse_retry_after),
        header_value_case_insensitive(headers, FCP_BACKPRESSURE_RETRY_AFTER_HEADER)
            .and_then(parse_retry_after),
    );

    Some(HostBackpressureSignal::new(reason, retry_after))
}

/// Decide whether a webhook delivery may retry after a host response.
#[must_use]
pub fn host_retry_decision_from_response<S: BuildHasher>(
    status: u16,
    headers: &HashMap<String, String, S>,
    default_delay: Duration,
) -> WebhookRetryDecision {
    let Some(signal) = host_backpressure_signal_from_response(status, headers) else {
        return WebhookRetryDecision::RetryAfter(default_delay);
    };

    if signal.is_budget_exhausted() {
        WebhookRetryDecision::RefuseRetry(signal)
    } else {
        WebhookRetryDecision::RetryAfter(
            signal
                .retry_after()
                .map_or(default_delay, |delay| default_delay.max(delay)),
        )
    }
}

/// Webhook errors.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// Invalid signature.
    #[error("Invalid webhook signature")]
    InvalidSignature,

    /// Signing secret is empty or whitespace-only.
    #[error("{algorithm} signing secret must not be empty")]
    EmptySigningSecret {
        /// Signature algorithm using the rejected secret.
        algorithm: SignatureAlgorithm,
    },

    /// Signing secret is below the algorithm-specific length floor.
    #[error("{algorithm} signing secret too short: {length} bytes is below minimum {min_length}")]
    SigningSecretTooShort {
        /// Signature algorithm using the rejected secret.
        algorithm: SignatureAlgorithm,
        /// Observed secret length.
        length: usize,
        /// Minimum accepted secret length.
        min_length: usize,
    },

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

    /// Replay cache is full.
    #[error("Replay cache full: {size} entries exceeds limit of {limit}")]
    ReplayCacheFull {
        /// Current cache size.
        size: usize,
        /// Maximum allowed entries.
        limit: usize,
    },

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
    fn empty_signing_secret_display() {
        let e = WebhookError::EmptySigningSecret {
            algorithm: SignatureAlgorithm::HmacSha256,
        };
        assert_eq!(
            e.to_string(),
            "HMAC-SHA256 signing secret must not be empty"
        );
    }

    #[test]
    fn signing_secret_too_short_display() {
        let e = WebhookError::SigningSecretTooShort {
            algorithm: SignatureAlgorithm::HmacSha1,
            length: 19,
            min_length: 20,
        };
        assert_eq!(
            e.to_string(),
            "HMAC-SHA1 signing secret too short: 19 bytes is below minimum 20"
        );
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
    fn replay_cache_full_display() {
        let e = WebhookError::ReplayCacheFull {
            size: 100_000,
            limit: 100_000,
        };
        assert_eq!(
            e.to_string(),
            "Replay cache full: 100000 entries exceeds limit of 100000"
        );
    }

    #[test]
    fn delivery_failed_display() {
        let e = WebhookError::DeliveryFailed("timeout".into());
        assert_eq!(e.to_string(), "Webhook delivery failed: timeout");
    }

    #[test]
    fn host_backpressure_signal_uses_max_retry_after() {
        let mut headers = HashMap::new();
        headers.insert(
            FCP_BACKPRESSURE_REASON_HEADER.to_string(),
            FCP_BACKPRESSURE_BUDGET_EXHAUSTED.to_string(),
        );
        headers.insert("Retry-After".to_string(), "5".to_string());
        headers.insert(
            FCP_BACKPRESSURE_RETRY_AFTER_HEADER.to_string(),
            "20".to_string(),
        );

        let signal = host_backpressure_signal_from_response(503, &headers)
            .expect("503 budget response should expose backpressure");

        assert!(signal.should_back_off());
        assert!(signal.is_budget_exhausted());
        assert_eq!(signal.retry_after(), Some(Duration::from_secs(20)));
    }

    #[test]
    fn host_retry_decision_refuses_budget_exhaustion() {
        let mut headers = HashMap::new();
        headers.insert(
            FCP_BACKPRESSURE_REASON_HEADER.to_string(),
            FCP_BACKPRESSURE_BUDGET_EXHAUSTED.to_string(),
        );
        headers.insert(
            FCP_BACKPRESSURE_RETRY_AFTER_HEADER.to_string(),
            "60".to_string(),
        );

        let decision = host_retry_decision_from_response(503, &headers, Duration::from_secs(1));

        assert!(matches!(
            decision,
            WebhookRetryDecision::RefuseRetry(signal)
                if signal.is_budget_exhausted()
                    && signal.retry_after() == Some(Duration::from_secs(60))
        ));
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

    // ── Batch 4: SunnyMoose additional test expansion ──

    #[test]
    fn error_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<WebhookError>();
        assert_sync::<WebhookError>();
    }

    #[test]
    fn timestamp_validation_negative_timestamp() {
        let e = WebhookError::TimestampValidation {
            reason: "negative".into(),
            timestamp: Some(-1),
            current_time: 1_000_000,
            tolerance: Duration::from_secs(60),
        };
        let display = e.to_string();
        assert!(display.contains("negative"));
    }

    #[test]
    fn timestamp_validation_zero_current_time() {
        let e = WebhookError::TimestampValidation {
            reason: "epoch".into(),
            timestamp: Some(0),
            current_time: 0,
            tolerance: Duration::from_secs(1),
        };
        assert_eq!(e.to_string(), "Timestamp validation failed: epoch");
    }

    #[test]
    fn replay_detected_empty_event_id() {
        let e = WebhookError::ReplayDetected {
            event_id: String::new(),
        };
        assert_eq!(e.to_string(), "Replay detected: event  already processed");
    }

    #[test]
    fn payload_too_large_equal_size_and_limit() {
        let e = WebhookError::PayloadTooLarge {
            size: 100,
            limit: 100,
        };
        assert_eq!(
            e.to_string(),
            "Payload too large: 100 bytes exceeds limit of 100"
        );
    }

    #[test]
    fn invalid_payload_long_message() {
        let msg = "x".repeat(5000);
        let e = WebhookError::InvalidPayload(msg.clone());
        let display = e.to_string();
        assert!(display.contains(&msg));
    }

    #[test]
    fn delivery_failed_multiline_message() {
        let e = WebhookError::DeliveryFailed("line1\nline2\nline3".into());
        let display = e.to_string();
        assert!(display.contains("line1\nline2\nline3"));
    }

    #[test]
    fn unsupported_event_type_special_chars() {
        let e = WebhookError::UnsupportedEventType("push:issue.*.opened[0]".into());
        let display = e.to_string();
        assert!(display.contains("push:issue.*.opened[0]"));
    }

    #[test]
    fn ip_not_allowed_cidr_format() {
        let e = WebhookError::IpNotAllowed("192.168.0.0/24".into());
        assert!(e.to_string().contains("192.168.0.0/24"));
    }

    #[test]
    fn error_debug_all_variants() {
        let variants: Vec<WebhookError> = vec![
            WebhookError::InvalidSignature,
            WebhookError::EmptySigningSecret {
                algorithm: SignatureAlgorithm::HmacSha1,
            },
            WebhookError::SigningSecretTooShort {
                algorithm: SignatureAlgorithm::HmacSha256,
                length: 15,
                min_length: 16,
            },
            WebhookError::MissingSignature("h".into()),
            WebhookError::TimestampValidation {
                reason: "r".into(),
                timestamp: Some(1),
                current_time: 2,
                tolerance: Duration::from_secs(3),
            },
            WebhookError::ReplayDetected {
                event_id: "e".into(),
            },
            WebhookError::PayloadTooLarge { size: 10, limit: 5 },
            WebhookError::InvalidPayload("p".into()),
            WebhookError::UnsupportedEventType("u".into()),
            WebhookError::ProviderNotConfigured("c".into()),
            WebhookError::IpNotAllowed("i".into()),
            WebhookError::ReplayCacheFull {
                size: 100_000,
                limit: 100_000,
            },
            WebhookError::DeliveryFailed("d".into()),
        ];
        for variant in variants {
            let debug = format!("{variant:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn error_source_for_replay_detected_is_none() {
        use std::error::Error;
        let e = WebhookError::ReplayDetected {
            event_id: "evt".into(),
        };
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_for_payload_too_large_is_none() {
        use std::error::Error;
        let e = WebhookError::PayloadTooLarge { size: 10, limit: 5 };
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_for_timestamp_validation_is_none() {
        use std::error::Error;
        let e = WebhookError::TimestampValidation {
            reason: "r".into(),
            timestamp: None,
            current_time: 0,
            tolerance: Duration::from_secs(0),
        };
        assert!(e.source().is_none());
    }

    // ── Batch 5: SunnyMoose test expansion ──

    #[test]
    fn missing_signature_with_newlines() {
        let e = WebhookError::MissingSignature("Header\nWith\nNewlines".into());
        let display = e.to_string();
        assert!(display.contains("Header\nWith\nNewlines"));
    }

    #[test]
    fn delivery_failed_with_unicode() {
        let e = WebhookError::DeliveryFailed("Verbindung fehlgeschlagen \u{2014} Zeitlimit".into());
        let display = e.to_string();
        assert!(display.contains('\u{2014}'));
    }

    #[test]
    fn replay_detected_long_event_id() {
        let long_id = "evt_".to_string() + &"x".repeat(5000);
        let e = WebhookError::ReplayDetected {
            event_id: long_id.clone(),
        };
        let display = e.to_string();
        assert!(display.contains(&long_id));
    }

    #[test]
    fn payload_too_large_zero_size() {
        let e = WebhookError::PayloadTooLarge { size: 0, limit: 0 };
        assert_eq!(
            e.to_string(),
            "Payload too large: 0 bytes exceeds limit of 0"
        );
    }

    #[test]
    fn timestamp_validation_min_max_current_time() {
        let e = WebhookError::TimestampValidation {
            reason: "boundary".into(),
            timestamp: Some(i64::MIN),
            current_time: i64::MAX,
            tolerance: Duration::from_secs(1),
        };
        let display = e.to_string();
        assert!(display.contains("boundary"));
    }

    #[test]
    fn ip_not_allowed_empty_string() {
        let e = WebhookError::IpNotAllowed(String::new());
        assert_eq!(e.to_string(), "IP address not in allowlist: ");
    }

    #[test]
    fn error_display_all_variants_not_empty() {
        use std::time::Duration;
        let variants: Vec<WebhookError> = vec![
            WebhookError::InvalidSignature,
            WebhookError::EmptySigningSecret {
                algorithm: SignatureAlgorithm::HmacSha256,
            },
            WebhookError::SigningSecretTooShort {
                algorithm: SignatureAlgorithm::HmacSha1,
                length: 19,
                min_length: 20,
            },
            WebhookError::MissingSignature(String::new()),
            WebhookError::TimestampValidation {
                reason: String::new(),
                timestamp: None,
                current_time: 0,
                tolerance: Duration::ZERO,
            },
            WebhookError::ReplayDetected {
                event_id: String::new(),
            },
            WebhookError::PayloadTooLarge { size: 0, limit: 0 },
            WebhookError::InvalidPayload(String::new()),
            WebhookError::UnsupportedEventType(String::new()),
            WebhookError::ProviderNotConfigured(String::new()),
            WebhookError::IpNotAllowed(String::new()),
            WebhookError::ReplayCacheFull { size: 0, limit: 0 },
            WebhookError::DeliveryFailed(String::new()),
        ];
        for v in variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn unsupported_event_type_unicode() {
        let e = WebhookError::UnsupportedEventType("\u{1F4E5} incoming".into());
        let display = e.to_string();
        assert!(display.contains('\u{1F4E5}'));
    }

    #[test]
    fn provider_not_configured_unicode() {
        let e = WebhookError::ProviderNotConfigured("c\u{00FC}stom".into());
        let display = e.to_string();
        assert!(display.contains("c\u{00FC}stom"));
    }

    #[test]
    fn invalid_payload_with_json_content() {
        let e = WebhookError::InvalidPayload(r#"{"error": "malformed"}"#.into());
        let display = e.to_string();
        assert!(display.contains("malformed"));
    }

    #[test]
    fn error_source_for_delivery_failed_is_none() {
        use std::error::Error;
        let e = WebhookError::DeliveryFailed("timeout".into());
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_for_unsupported_event_type_is_none() {
        use std::error::Error;
        let e = WebhookError::UnsupportedEventType("unknown".into());
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_for_provider_not_configured_is_none() {
        use std::error::Error;
        let e = WebhookError::ProviderNotConfigured("x".into());
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_for_ip_not_allowed_is_none() {
        use std::error::Error;
        let e = WebhookError::IpNotAllowed("1.2.3.4".into());
        assert!(e.source().is_none());
    }

    #[test]
    fn json_error_display_contains_json_parsing_prefix() {
        let json_err: Result<serde_json::Value, _> = serde_json::from_str("{{{}}}");
        let e: WebhookError = json_err.unwrap_err().into();
        assert!(e.to_string().starts_with("JSON parsing error:"));
    }

    #[test]
    fn hex_error_display_contains_hex_decoding_prefix() {
        let hex_err = hex::decode("gg").unwrap_err();
        let e: WebhookError = hex_err.into();
        assert!(e.to_string().starts_with("Hex decoding error:"));
    }
}
