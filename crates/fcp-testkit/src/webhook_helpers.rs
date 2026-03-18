//! Webhook and signature verification test helpers.
//!
//! Provides utilities for testing webhook connectors: HMAC signature generation,
//! payload builders, delivery simulation, and provider-specific helpers.
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::webhook_helpers::{WebhookPayloadBuilder, sign_hmac_sha256};
//!
//! let secret = "whsec_test123";
//! let payload = WebhookPayloadBuilder::new("issue.created")
//!     .with_json_body(serde_json::json!({"action": "opened"}))
//!     .build();
//! let signature = sign_hmac_sha256(secret, &payload.body);
//! assert!(!signature.is_empty());
//! ```

use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// HMAC Signature Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute HMAC-SHA256 signature over a payload using the given secret.
///
/// Returns the hex-encoded signature string.
///
/// # Panics
///
/// Panics if the HMAC key is invalid (should never happen for any-length key).
#[must_use]
pub fn sign_hmac_sha256(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key length is always valid");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Compute HMAC-SHA256 and return it with a prefix (e.g., `sha256=abc123`).
#[must_use]
pub fn sign_hmac_sha256_prefixed(secret: &str, payload: &[u8], prefix: &str) -> String {
    format!("{prefix}{}", sign_hmac_sha256(secret, payload))
}

/// Verify an HMAC-SHA256 signature against a payload.
#[must_use]
pub fn verify_hmac_sha256(secret: &str, payload: &[u8], expected_hex: &str) -> bool {
    let computed = sign_hmac_sha256(secret, payload);
    constant_time_eq(computed.as_bytes(), expected_hex.as_bytes())
}

/// Constant-time byte comparison to prevent timing attacks in tests.
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Provider-Specific Signature Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a GitHub-style webhook signature header value.
///
/// GitHub uses `sha256=<hex>` format in the `X-Hub-Signature-256` header.
#[must_use]
pub fn github_signature(secret: &str, payload: &[u8]) -> String {
    sign_hmac_sha256_prefixed(secret, payload, "sha256=")
}

/// Generate a Stripe-style webhook signature header value.
///
/// Stripe uses `t=<timestamp>,v1=<hex>` format in the `Stripe-Signature` header.
#[must_use]
pub fn stripe_signature(secret: &str, payload: &[u8], timestamp: i64) -> String {
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(payload));
    let sig = sign_hmac_sha256(secret, signed_payload.as_bytes());
    format!("t={timestamp},v1={sig}")
}

/// Generate a Slack-style request signature.
///
/// Slack uses `v0=<hex>` with `v0:<timestamp>:<body>` as the signing base.
#[must_use]
pub fn slack_signature(signing_secret: &str, timestamp: &str, body: &str) -> String {
    let base = format!("v0:{timestamp}:{body}");
    sign_hmac_sha256_prefixed(signing_secret, base.as_bytes(), "v0=")
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhook Payload Builder
// ─────────────────────────────────────────────────────────────────────────────

/// A test webhook payload with event type, headers, and body.
#[derive(Debug, Clone)]
pub struct WebhookPayload {
    /// The event type (e.g., `issue.created`, `payment_intent.succeeded`).
    pub event_type: String,
    /// The raw body bytes.
    pub body: Vec<u8>,
    /// Headers to include with the webhook delivery.
    pub headers: Vec<(String, String)>,
}

/// Builder for constructing test webhook payloads.
pub struct WebhookPayloadBuilder {
    event_type: String,
    body: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
}

impl WebhookPayloadBuilder {
    /// Create a new builder for the given event type.
    #[must_use]
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            body: None,
            headers: Vec::new(),
        }
    }

    /// Set a JSON body for the webhook payload.
    #[must_use]
    pub fn with_json_body(mut self, value: Value) -> Self {
        self.body = Some(value.to_string().into_bytes());
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        self
    }

    /// Set a raw body for the webhook payload.
    #[must_use]
    pub fn with_raw_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Add a header to the webhook payload.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Sign the payload with HMAC-SHA256 and add the signature as a header.
    #[must_use]
    pub fn sign_github(mut self, secret: &str) -> Self {
        let body = self.body.as_deref().unwrap_or_default();
        let sig = github_signature(secret, body);
        self.headers
            .push(("X-Hub-Signature-256".to_string(), sig));
        self.headers
            .push(("X-GitHub-Event".to_string(), self.event_type.clone()));
        self
    }

    /// Sign the payload with Stripe's signature scheme.
    #[must_use]
    pub fn sign_stripe(mut self, secret: &str, timestamp: i64) -> Self {
        let body = self.body.as_deref().unwrap_or_default();
        let sig = stripe_signature(secret, body, timestamp);
        self.headers.push(("Stripe-Signature".to_string(), sig));
        self
    }

    /// Build the final webhook payload.
    #[must_use]
    pub fn build(self) -> WebhookPayload {
        WebhookPayload {
            event_type: self.event_type,
            body: self.body.unwrap_or_default(),
            headers: self.headers,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhook Delivery Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that a webhook signature header is present and valid.
///
/// # Panics
///
/// Panics if the header is missing or the signature doesn't verify.
pub fn assert_webhook_signature_valid(
    headers: &[(String, String)],
    header_name: &str,
    secret: &str,
    payload: &[u8],
) {
    let sig_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(header_name))
        .unwrap_or_else(|| panic!("Missing webhook signature header: {header_name}"));

    // Strip common prefixes for verification
    let sig_hex = sig_header
        .1
        .strip_prefix("sha256=")
        .or_else(|| sig_header.1.strip_prefix("v0="))
        .unwrap_or(&sig_header.1);

    assert!(
        verify_hmac_sha256(secret, payload, sig_hex),
        "Webhook signature verification failed for header {header_name}"
    );
}

/// Assert that a webhook payload contains the expected event type header.
///
/// # Panics
///
/// Panics if the event type header is missing or doesn't match.
pub fn assert_webhook_event_type(
    headers: &[(String, String)],
    header_name: &str,
    expected_event: &str,
) {
    let event_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(header_name))
        .unwrap_or_else(|| panic!("Missing event type header: {header_name}"));

    assert_eq!(
        event_header.1, expected_event,
        "Expected event type '{expected_event}' but got '{}'",
        event_header.1
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_sign_and_verify() {
        let secret = "test-secret-key";
        let payload = b"hello world";
        let sig = sign_hmac_sha256(secret, payload);
        assert!(!sig.is_empty());
        assert!(verify_hmac_sha256(secret, payload, &sig));
        assert!(!verify_hmac_sha256("wrong-secret", payload, &sig));
    }

    #[test]
    fn test_hmac_sha256_prefixed() {
        let sig = sign_hmac_sha256_prefixed("secret", b"data", "sha256=");
        assert!(sig.starts_with("sha256="));
        assert!(sig.len() > "sha256=".len());
    }

    #[test]
    fn test_github_signature_format() {
        let sig = github_signature("secret", b"payload");
        assert!(sig.starts_with("sha256="));
    }

    #[test]
    fn test_stripe_signature_format() {
        let sig = stripe_signature("whsec_test", b"payload", 1_234_567_890);
        assert!(sig.starts_with("t=1234567890,v1="));
    }

    #[test]
    fn test_slack_signature_format() {
        let sig = slack_signature("signing_secret", "1531420618", "token=xyzz0");
        assert!(sig.starts_with("v0="));
    }

    #[test]
    fn test_webhook_payload_builder_basic() {
        let payload = WebhookPayloadBuilder::new("push")
            .with_json_body(serde_json::json!({"ref": "main"}))
            .build();
        assert_eq!(payload.event_type, "push");
        assert!(!payload.body.is_empty());
        assert!(payload
            .headers
            .iter()
            .any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn test_webhook_payload_builder_github_signed() {
        let secret = "gh-webhook-secret";
        let payload = WebhookPayloadBuilder::new("issues")
            .with_json_body(serde_json::json!({"action": "opened"}))
            .sign_github(secret)
            .build();

        assert!(payload
            .headers
            .iter()
            .any(|(k, _)| k == "X-Hub-Signature-256"));
        assert!(payload
            .headers
            .iter()
            .any(|(k, _)| k == "X-GitHub-Event"));

        assert_webhook_signature_valid(
            &payload.headers,
            "X-Hub-Signature-256",
            secret,
            &payload.body,
        );
    }

    #[test]
    fn test_webhook_payload_builder_stripe_signed() {
        let secret = "whsec_test123";
        let ts = 1_700_000_000;
        let payload = WebhookPayloadBuilder::new("payment_intent.succeeded")
            .with_json_body(serde_json::json!({"id": "pi_123"}))
            .sign_stripe(secret, ts)
            .build();

        assert!(payload
            .headers
            .iter()
            .any(|(k, _)| k == "Stripe-Signature"));
    }

    #[test]
    fn test_webhook_event_type_assertion() {
        let headers = vec![
            ("X-GitHub-Event".to_string(), "push".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        assert_webhook_event_type(&headers, "X-GitHub-Event", "push");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_raw_body_payload() {
        let payload = WebhookPayloadBuilder::new("raw.event")
            .with_raw_body(b"raw body content".to_vec())
            .with_header("X-Custom", "value")
            .build();
        assert_eq!(payload.body, b"raw body content");
        assert!(payload.headers.iter().any(|(k, v)| k == "X-Custom" && v == "value"));
    }

    #[test]
    fn test_empty_payload() {
        let payload = WebhookPayloadBuilder::new("ping").build();
        assert!(payload.body.is_empty());
        assert_eq!(payload.event_type, "ping");
    }
}
