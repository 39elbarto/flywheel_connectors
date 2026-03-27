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
//!     .with_json_body(&serde_json::json!({"action": "opened"}))
//!     .build();
//! let signature = sign_hmac_sha256(secret, &payload.body);
//! assert!(!signature.is_empty());
//! ```

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::Value;
use sha2::Sha256;

use crate::{HttpFixtureResponse, HttpFixtureRoute, HttpFixtureServer};

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
    let mut signed_payload = format!("{timestamp}.").into_bytes();
    signed_payload.extend_from_slice(payload);
    let sig = sign_hmac_sha256(secret, &signed_payload);
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
    pub fn with_json_body(mut self, value: &Value) -> Self {
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
        self.headers.push(("X-Hub-Signature-256".to_string(), sig));
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

    let sig_hex = match header_name.to_ascii_lowercase().as_str() {
        "stripe-signature" => {
            let mut timestamp = None;
            let mut signatures = Vec::new();
            for part in sig_header.1.split(',') {
                if let Some(ts) = part.strip_prefix("t=") {
                    timestamp = ts.parse::<i64>().ok();
                } else if let Some(sig) = part.strip_prefix("v1=") {
                    signatures.push(sig);
                }
            }

            let timestamp = timestamp.unwrap_or_else(|| {
                panic!(
                    "Stripe signature header missing timestamp: {}",
                    sig_header.1
                )
            });
            assert!(
                !signatures.is_empty(),
                "Stripe signature header missing v1 signature: {}",
                sig_header.1
            );

            let mut signed_payload = format!("{timestamp}.").into_bytes();
            signed_payload.extend_from_slice(payload);

            assert!(
                signatures.iter().any(|signature| verify_hmac_sha256(
                    secret,
                    &signed_payload,
                    signature
                )),
                "Webhook signature verification failed for header {header_name}"
            );
            return;
        }
        _ => sig_header
            .1
            .strip_prefix("sha256=")
            .or_else(|| sig_header.1.strip_prefix("v0="))
            .unwrap_or(&sig_header.1),
    };

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
// Webhook Ingress Harness
// ─────────────────────────────────────────────────────────────────────────────

/// Retry policy for webhook ingress delivery attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRetryPolicy {
    /// Maximum number of delivery attempts.
    pub max_attempts: usize,
    /// Response statuses that should trigger another attempt.
    pub retry_statuses: Vec<u16>,
    /// Delay between attempts.
    pub delay: Duration,
}

impl Default for WebhookRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            retry_statuses: vec![429, 500, 502, 503, 504],
            delay: Duration::from_millis(50),
        }
    }
}

impl WebhookRetryPolicy {
    /// Create a retry policy with the given maximum attempts.
    #[must_use]
    pub fn new(max_attempts: usize) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            ..Self::default()
        }
    }

    /// Override the delay between attempts.
    #[must_use]
    pub const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Add a response status that should be retried.
    #[must_use]
    pub fn with_retry_status(mut self, status: u16) -> Self {
        if !self.retry_statuses.contains(&status) {
            self.retry_statuses.push(status);
        }
        self
    }
}

/// One webhook delivery attempt captured by the ingress harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDeliveryAttemptRecord {
    /// 1-based attempt number.
    pub attempt: usize,
    /// Wall-clock time when the attempt started.
    pub started_at: DateTime<Utc>,
    /// HTTP status from the target, when a response was received.
    pub status: Option<u16>,
    /// Attempt duration.
    pub duration: Duration,
    /// Response body bytes captured from the target.
    pub response_body: Vec<u8>,
    /// Transport or response-read error when the attempt failed.
    pub error: Option<String>,
}

impl WebhookDeliveryAttemptRecord {
    /// True when the attempt completed with a 2xx response and no error.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.error.is_none()
            && self
                .status
                .is_some_and(|status| (200..300).contains(&status))
    }
}

/// Recorded transcript for a webhook ingress delivery sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookIngressTranscript {
    /// Target endpoint URL that received the webhook deliveries.
    pub endpoint: String,
    /// Event type associated with the payload.
    pub event_type: String,
    /// Attempt-by-attempt delivery records.
    pub attempts: Vec<WebhookDeliveryAttemptRecord>,
}

impl WebhookIngressTranscript {
    /// Status of the final attempt, if one was received.
    #[must_use]
    pub fn last_status(&self) -> Option<u16> {
        self.attempts.last().and_then(|attempt| attempt.status)
    }

    /// True when the final attempt succeeded with a 2xx response.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.attempts
            .last()
            .is_some_and(WebhookDeliveryAttemptRecord::is_success)
    }
}

/// Attachment/media fixture mounted on a local HTTP server for webhook tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookAttachmentFixture {
    /// Absolute URL that webhook payloads can reference.
    pub url: String,
    /// Response content type.
    pub content_type: String,
    /// Size of the served payload in bytes.
    pub size_bytes: usize,
}

impl WebhookAttachmentFixture {
    /// Mount a binary attachment on the provided fixture server and return its URL.
    #[must_use]
    pub fn mount_binary(
        fixture: &HttpFixtureServer,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Self {
        let size_bytes = body.len();
        fixture.mount(
            HttpFixtureRoute::get(path)
                .respond_with(HttpFixtureResponse::binary(body, content_type)),
        );
        Self {
            url: format!("{}{}", fixture.base_url(), path),
            content_type: content_type.to_string(),
            size_bytes,
        }
    }

    /// Mount a JSON attachment on the provided fixture server and return its URL.
    ///
    /// # Panics
    ///
    /// Panics if the JSON body cannot be serialized to bytes.
    #[must_use]
    pub fn mount_json(fixture: &HttpFixtureServer, path: &str, body: &Value) -> Self {
        let encoded =
            serde_json::to_vec(body).expect("Webhook attachment JSON serialization should succeed");
        let size_bytes = encoded.len();
        fixture.mount(
            HttpFixtureRoute::get(path).respond_with(HttpFixtureResponse::json(body.clone())),
        );
        Self {
            url: format!("{}{}", fixture.base_url(), path),
            content_type: "application/json".to_string(),
            size_bytes,
        }
    }
}

/// Real-network webhook ingress harness that posts payloads to a target endpoint.
#[derive(Debug, Clone)]
pub struct WebhookIngressHarness {
    endpoint: String,
    client: Client,
}

impl WebhookIngressHarness {
    /// Create a harness bound to a single webhook target endpoint.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: Client::new(),
        }
    }

    /// Target endpoint used by the harness.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn send_once(
        &self,
        payload: &WebhookPayload,
        attempt: usize,
    ) -> WebhookDeliveryAttemptRecord {
        let started_at = Utc::now();
        let timer = Instant::now();

        let mut request = self.client.post(&self.endpoint);
        for (name, value) in &payload.headers {
            request = request.header(name, value);
        }

        match request.body(payload.body.clone()).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                match response.bytes().await {
                    Ok(body) => WebhookDeliveryAttemptRecord {
                        attempt,
                        started_at,
                        status: Some(status),
                        duration: timer.elapsed(),
                        response_body: body.to_vec(),
                        error: None,
                    },
                    Err(err) => WebhookDeliveryAttemptRecord {
                        attempt,
                        started_at,
                        status: Some(status),
                        duration: timer.elapsed(),
                        response_body: Vec::new(),
                        error: Some(err.to_string()),
                    },
                }
            }
            Err(err) => WebhookDeliveryAttemptRecord {
                attempt,
                started_at,
                status: None,
                duration: timer.elapsed(),
                response_body: Vec::new(),
                error: Some(err.to_string()),
            },
        }
    }

    /// Deliver a payload once and return a single-attempt transcript.
    pub async fn deliver(&self, payload: &WebhookPayload) -> WebhookIngressTranscript {
        self.deliver_with_retry(payload, &WebhookRetryPolicy::default())
            .await
    }

    /// Deliver a payload repeatedly according to the retry policy.
    pub async fn deliver_with_retry(
        &self,
        payload: &WebhookPayload,
        policy: &WebhookRetryPolicy,
    ) -> WebhookIngressTranscript {
        let max_attempts = policy.max_attempts.max(1);
        let mut transcript = WebhookIngressTranscript {
            endpoint: self.endpoint.clone(),
            event_type: payload.event_type.clone(),
            attempts: Vec::with_capacity(max_attempts),
        };

        for attempt in 1..=max_attempts {
            let record = self.send_once(payload, attempt).await;
            let should_retry = attempt < max_attempts
                && record.status.is_none_or(|status| policy.retry_statuses.contains(&status));
            transcript.attempts.push(record);

            if !should_retry {
                break;
            }

            if !policy.delay.is_zero() {
                fcp_async_core::time::sleep(policy.delay).await;
            }
        }

        transcript
    }

    /// Deliver the same payload multiple times to exercise duplicate-delivery handling.
    pub async fn deliver_duplicates(
        &self,
        payload: &WebhookPayload,
        count: usize,
    ) -> WebhookIngressTranscript {
        let deliveries = count.max(1);
        let mut transcript = WebhookIngressTranscript {
            endpoint: self.endpoint.clone(),
            event_type: payload.event_type.clone(),
            attempts: Vec::with_capacity(deliveries),
        };

        for attempt in 1..=deliveries {
            transcript
                .attempts
                .push(self.send_once(payload, attempt).await);
        }

        transcript
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

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
            .with_json_body(&serde_json::json!({"ref": "main"}))
            .build();
        assert_eq!(payload.event_type, "push");
        assert!(!payload.body.is_empty());
        assert!(payload.headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn test_webhook_payload_builder_github_signed() {
        let secret = "gh-webhook-secret";
        let payload = WebhookPayloadBuilder::new("issues")
            .with_json_body(&serde_json::json!({"action": "opened"}))
            .sign_github(secret)
            .build();

        assert!(
            payload
                .headers
                .iter()
                .any(|(k, _)| k == "X-Hub-Signature-256")
        );
        assert!(payload.headers.iter().any(|(k, _)| k == "X-GitHub-Event"));

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
            .with_json_body(&serde_json::json!({"id": "pi_123"}))
            .sign_stripe(secret, ts)
            .build();

        assert!(payload.headers.iter().any(|(k, _)| k == "Stripe-Signature"));
        assert_webhook_signature_valid(&payload.headers, "Stripe-Signature", secret, &payload.body);
    }

    #[test]
    fn test_stripe_signature_uses_raw_payload_bytes() {
        let secret = "whsec_test123";
        let ts = 1_700_000_000;
        let payload = vec![0xf0, 0x28, 0x8c, 0x28];
        let sig = stripe_signature(secret, &payload, ts);

        let headers = vec![("Stripe-Signature".to_string(), sig)];
        assert_webhook_signature_valid(&headers, "Stripe-Signature", secret, &payload);
    }

    #[test]
    fn test_stripe_signature_accepts_any_valid_v1_value() {
        let secret = "whsec_test123";
        let ts = 1_700_000_000;
        let payload = br#"{"id":"evt_123"}"#.to_vec();
        let valid_sig = stripe_signature(secret, &payload, ts);
        let valid_sig = valid_sig
            .strip_prefix(&format!("t={ts},v1="))
            .expect("generated Stripe signature should include timestamp and v1 digest");
        let header_value = format!("t={ts},v1=invalid,v1={valid_sig}");
        let headers = vec![("Stripe-Signature".to_string(), header_value)];

        assert_webhook_signature_valid(&headers, "Stripe-Signature", secret, &payload);
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
        assert!(
            payload
                .headers
                .iter()
                .any(|(k, v)| k == "X-Custom" && v == "value")
        );
    }

    #[test]
    fn test_empty_payload() {
        let payload = WebhookPayloadBuilder::new("ping").build();
        assert!(payload.body.is_empty());
        assert_eq!(payload.event_type, "ping");
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_ingress_harness_delivers_signed_payload() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::post("/hooks/github")
                .respond_with(HttpFixtureResponse::text(202, "accepted")),
        );

        let secret = "gh-secret";
        let payload = WebhookPayloadBuilder::new("push")
            .with_json_body(&serde_json::json!({"ref": "refs/heads/main"}))
            .sign_github(secret)
            .build();
        let harness = WebhookIngressHarness::new(format!("{}/hooks/github", fixture.base_url()));

        let transcript = harness.deliver(&payload).await;

        assert!(transcript.succeeded());
        assert_eq!(transcript.attempts.len(), 1);
        assert_eq!(transcript.last_status(), Some(202));

        let requests = fixture.recorded_requests();
        assert_eq!(requests.len(), 1);
        assert_webhook_signature_valid(
            &requests[0].headers,
            "X-Hub-Signature-256",
            secret,
            &payload.body,
        );
        assert_webhook_event_type(&requests[0].headers, "X-GitHub-Event", "push");
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_ingress_harness_retries_retryable_statuses() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::post("/hooks/retry")
                .respond_with(HttpFixtureResponse::text(500, "retry me"))
                .respond_with(HttpFixtureResponse::text(202, "ok")),
        );

        let payload = WebhookPayloadBuilder::new("delivery.retry")
            .with_json_body(&serde_json::json!({"id": "evt_retry"}))
            .build();
        let harness = WebhookIngressHarness::new(format!("{}/hooks/retry", fixture.base_url()));
        let policy = WebhookRetryPolicy::new(3)
            .with_delay(Duration::from_millis(1))
            .with_retry_status(500);

        let transcript = harness.deliver_with_retry(&payload, &policy).await;

        assert!(transcript.succeeded());
        assert_eq!(transcript.attempts.len(), 2);
        assert_eq!(transcript.attempts[0].status, Some(500));
        assert_eq!(transcript.attempts[1].status, Some(202));
        fixture.assert_request_count(2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_ingress_harness_records_transport_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
        let address = listener.local_addr().expect("local addr");
        drop(listener);

        let payload = WebhookPayloadBuilder::new("listener.restart")
            .with_json_body(&serde_json::json!({"id": "evt_transport"}))
            .build();
        let harness = WebhookIngressHarness::new(format!("http://{address}/hooks/restart"));
        let policy = WebhookRetryPolicy::new(2).with_delay(Duration::from_millis(1));

        let transcript = harness.deliver_with_retry(&payload, &policy).await;

        assert_eq!(transcript.attempts.len(), 2);
        assert!(
            transcript
                .attempts
                .iter()
                .all(|attempt| attempt.status.is_none())
        );
        assert!(
            transcript
                .attempts
                .iter()
                .all(|attempt| attempt.error.is_some())
        );
        assert!(!transcript.succeeded());
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_ingress_harness_delivers_duplicates() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        fixture.mount(
            HttpFixtureRoute::post("/hooks/duplicate")
                .respond_with(HttpFixtureResponse::text(202, "first"))
                .respond_with(HttpFixtureResponse::text(202, "second")),
        );

        let payload = WebhookPayloadBuilder::new("delivery.duplicate")
            .with_json_body(&serde_json::json!({"id": "evt_dup"}))
            .build();
        let harness = WebhookIngressHarness::new(format!("{}/hooks/duplicate", fixture.base_url()));

        let transcript = harness.deliver_duplicates(&payload, 2).await;

        assert_eq!(transcript.attempts.len(), 2);
        assert!(
            transcript
                .attempts
                .iter()
                .all(WebhookDeliveryAttemptRecord::is_success)
        );

        let requests = fixture.recorded_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
    }

    #[fcp_async_core::runtime::test]
    async fn test_attachment_fixture_mounts_binary_payload() {
        let fixture = HttpFixtureServer::start().expect("fixture should bind");
        let attachment = WebhookAttachmentFixture::mount_binary(
            &fixture,
            "/attachments/report.bin",
            vec![1, 2, 3, 4],
            "application/octet-stream",
        );

        let response = reqwest::get(&attachment.url)
            .await
            .expect("attachment fetch");

        assert_eq!(attachment.content_type, "application/octet-stream");
        assert_eq!(attachment.size_bytes, 4);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
        assert_eq!(
            response.bytes().await.expect("attachment bytes").as_ref(),
            &[1, 2, 3, 4]
        );
    }
}
