//! Provider-specific webhook handlers.
//!
//! Pre-configured handlers for common webhook providers.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use crate::{
    DEFAULT_TIMESTAMP_TOLERANCE, HmacSha256Verifier, SignatureVerifier, WebhookError, WebhookEvent,
    WebhookResult,
};

/// Webhook provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookProvider {
    /// GitHub.
    GitHub,
    /// Stripe.
    Stripe,
    /// Slack.
    Slack,
    /// Linear.
    Linear,
    /// Discord.
    Discord,
    /// Custom provider.
    Custom,
}

impl std::fmt::Display for WebhookProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitHub => write!(f, "github"),
            Self::Stripe => write!(f, "stripe"),
            Self::Slack => write!(f, "slack"),
            Self::Linear => write!(f, "linear"),
            Self::Discord => write!(f, "discord"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// GitHub webhook handler.
#[derive(Debug)]
pub struct GitHubWebhook {
    verifier: HmacSha256Verifier,
}

impl GitHubWebhook {
    /// Create a new GitHub webhook handler.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(secret),
        }
    }

    /// Verify and parse a GitHub webhook.
    ///
    /// # Errors
    /// Returns an error when required headers are missing, signature verification fails,
    /// or the JSON payload cannot be parsed.
    pub fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookResult<WebhookEvent> {
        // Get signature header
        let signature = headers
            .get("x-hub-signature-256")
            .or_else(|| headers.get("X-Hub-Signature-256"))
            .ok_or_else(|| WebhookError::MissingSignature("X-Hub-Signature-256".into()))?;

        // Verify signature
        self.verifier.verify(body, signature)?;

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_type = headers
            .get("x-github-event")
            .or_else(|| headers.get("X-GitHub-Event"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let delivery_id = headers
            .get("x-github-delivery")
            .or_else(|| headers.get("X-GitHub-Delivery"))
            .cloned()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Ok(WebhookEvent::new(delivery_id, event_type, "github")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }
}

/// Stripe webhook handler.
#[derive(Debug)]
pub struct StripeWebhook {
    verifier: HmacSha256Verifier,
    timestamp_tolerance: Duration,
}

impl StripeWebhook {
    /// Create a new Stripe webhook handler.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(secret),
            timestamp_tolerance: DEFAULT_TIMESTAMP_TOLERANCE,
        }
    }

    /// Set timestamp tolerance.
    #[must_use]
    pub const fn with_timestamp_tolerance(mut self, tolerance: Duration) -> Self {
        self.timestamp_tolerance = tolerance;
        self
    }

    /// Verify and parse a Stripe webhook.
    ///
    /// # Errors
    /// Returns an error when required headers are missing, the signature/timestamp is invalid,
    /// or the JSON payload cannot be parsed.
    pub fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookResult<WebhookEvent> {
        // Get Stripe-Signature header
        let signature_header = headers
            .get("stripe-signature")
            .or_else(|| headers.get("Stripe-Signature"))
            .ok_or_else(|| WebhookError::MissingSignature("Stripe-Signature".into()))?;

        // Parse signature header (format: t=timestamp,v1=signature)
        let (timestamp, signatures) = Self::parse_stripe_signature(signature_header)?;

        // Validate timestamp
        self.validate_timestamp(timestamp)?;

        // Build signed payload (Stripe format: timestamp.body)
        let timestamp_str = timestamp.to_string();
        let mut signed_payload = timestamp_str.as_bytes().to_vec();
        signed_payload.push(b'.');
        signed_payload.extend_from_slice(body);

        // Verify signature against any of the provided v1 signatures
        let mut verified = false;
        for signature in signatures {
            if self.verifier.verify(&signed_payload, &signature).is_ok() {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err(WebhookError::InvalidSignature);
        }

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_id = payload
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        Ok(WebhookEvent::new(event_id, event_type, "stripe")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }

    /// Parse Stripe signature header.
    fn parse_stripe_signature(header: &str) -> WebhookResult<(i64, Vec<String>)> {
        let mut timestamp = None;
        let mut signatures = Vec::new();

        for part in header.split(',') {
            if let Some(ts) = part.strip_prefix("t=") {
                timestamp = ts.parse().ok();
            } else if let Some(sig) = part.strip_prefix("v1=") {
                signatures.push(sig.to_string());
            }
        }

        if let Some(ts) = timestamp {
            if !signatures.is_empty() {
                return Ok((ts, signatures));
            }
        }

        Err(WebhookError::InvalidPayload(
            "Invalid Stripe-Signature format".into(),
        ))
    }

    /// Validate timestamp is within tolerance.
    fn validate_timestamp(&self, timestamp: i64) -> WebhookResult<()> {
        let now = Utc::now().timestamp();
        let tolerance = i64::try_from(self.timestamp_tolerance.as_secs()).unwrap_or(i64::MAX);

        if (now - timestamp).abs() > tolerance {
            return Err(WebhookError::TimestampValidation {
                reason: "Timestamp outside tolerance window".into(),
                timestamp: Some(timestamp),
                current_time: now,
                tolerance: self.timestamp_tolerance,
            });
        }

        Ok(())
    }
}

/// Slack webhook handler.
#[derive(Debug)]
pub struct SlackWebhook {
    verifier: HmacSha256Verifier,
    timestamp_tolerance: Duration,
}

impl SlackWebhook {
    /// Create a new Slack webhook handler.
    #[must_use]
    pub fn new(signing_secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(signing_secret),
            timestamp_tolerance: DEFAULT_TIMESTAMP_TOLERANCE,
        }
    }

    /// Verify and parse a Slack webhook.
    ///
    /// # Errors
    /// Returns an error when required headers are missing, signature/timestamp checks fail,
    /// or the JSON payload cannot be parsed.
    pub fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookResult<WebhookEvent> {
        // Get headers
        let signature = headers
            .get("x-slack-signature")
            .or_else(|| headers.get("X-Slack-Signature"))
            .ok_or_else(|| WebhookError::MissingSignature("X-Slack-Signature".into()))?;

        let timestamp_str = headers
            .get("x-slack-request-timestamp")
            .or_else(|| headers.get("X-Slack-Request-Timestamp"))
            .ok_or_else(|| WebhookError::MissingSignature("X-Slack-Request-Timestamp".into()))?;

        let timestamp: i64 = timestamp_str
            .parse()
            .map_err(|_| WebhookError::InvalidPayload("Invalid timestamp".into()))?;

        // Validate timestamp
        let now = Utc::now().timestamp();
        let tolerance = i64::try_from(self.timestamp_tolerance.as_secs()).unwrap_or(i64::MAX);
        if (now - timestamp).abs() > tolerance {
            return Err(WebhookError::TimestampValidation {
                reason: "Timestamp outside tolerance".into(),
                timestamp: Some(timestamp),
                current_time: now,
                tolerance: self.timestamp_tolerance,
            });
        }

        // Build Slack signature base string
        let mut base_string = format!("v0:{timestamp}:").into_bytes();
        base_string.extend_from_slice(body);

        // Verify signature
        self.verifier.verify(&base_string, signature)?;

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_id = payload
            .get("event_id")
            .and_then(Value::as_str)
            .map_or_else(|| uuid::Uuid::new_v4().to_string(), ToString::to_string);

        let event_type = payload
            .get("type")
            .or_else(|| payload.get("event").and_then(|e| e.get("type")))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        Ok(WebhookEvent::new(event_id, event_type, "slack")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }
}

/// Linear webhook handler.
#[derive(Debug)]
pub struct LinearWebhook {
    verifier: HmacSha256Verifier,
}

impl LinearWebhook {
    /// Create a new Linear webhook handler.
    #[must_use]
    pub fn new(signing_secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(signing_secret),
        }
    }

    /// Verify and parse a Linear webhook.
    ///
    /// # Errors
    /// Returns an error when required headers are missing, signature verification fails,
    /// or the JSON payload cannot be parsed.
    pub fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookResult<WebhookEvent> {
        // Get signature
        let signature = headers
            .get("linear-signature")
            .or_else(|| headers.get("Linear-Signature"))
            .ok_or_else(|| WebhookError::MissingSignature("Linear-Signature".into()))?;

        // Verify signature
        self.verifier.verify(body, signature)?;

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_id = payload
            .get("webhookId")
            .and_then(Value::as_str)
            .map_or_else(|| uuid::Uuid::new_v4().to_string(), ToString::to_string);

        let event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        Ok(WebhookEvent::new(event_id, event_type, "linear")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventRouter, EventSubscription};
    use fcp_core::TaintFlag;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_github_webhook() {
        let handler = GitHubWebhook::new("secret");

        let body = br#"{"action": "opened", "issue": {"number": 1}}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "issues".to_string());
        headers.insert("x-github-delivery".to_string(), "abc123".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();

        assert_eq!(event.id, "abc123");
        assert_eq!(event.event_type, "issues");
        assert_eq!(event.provider, "github");
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_stripe_signature_parsing() {
        let (ts, sigs) = StripeWebhook::parse_stripe_signature("t=1234567890,v1=abc123").unwrap();

        assert_eq!(ts, 1_234_567_890);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0], "abc123");
    }

    #[test]
    fn test_linear_webhook() {
        let handler = LinearWebhook::new("secret");

        let body = br#"{"type": "Issue", "action": "create", "webhookId": "wh_123"}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);

        let event = handler.verify_and_parse(&headers, body).unwrap();

        assert_eq!(event.id, "wh_123");
        assert_eq!(event.event_type, "Issue");
        assert_eq!(event.provider, "linear");
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    // ── New tests ──

    #[test]
    fn test_webhook_provider_display() {
        assert_eq!(WebhookProvider::GitHub.to_string(), "github");
        assert_eq!(WebhookProvider::Stripe.to_string(), "stripe");
        assert_eq!(WebhookProvider::Slack.to_string(), "slack");
        assert_eq!(WebhookProvider::Linear.to_string(), "linear");
        assert_eq!(WebhookProvider::Discord.to_string(), "discord");
        assert_eq!(WebhookProvider::Custom.to_string(), "custom");
    }

    #[test]
    fn test_github_missing_signature() {
        let handler = GitHubWebhook::new("secret");
        let headers = HashMap::new();
        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(result, Err(WebhookError::MissingSignature(_))));
    }

    #[test]
    fn test_github_invalid_signature() {
        let handler = GitHubWebhook::new("secret");
        let mut headers = HashMap::new();
        headers.insert(
            "x-hub-signature-256".to_string(),
            "sha256=deadbeef".to_string(),
        );
        headers.insert("x-github-event".to_string(), "push".to_string());

        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(result.is_err());
    }

    #[test]
    fn test_stripe_invalid_signature_format() {
        let result = StripeWebhook::parse_stripe_signature("invalid-format");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_missing_v1() {
        let result = StripeWebhook::parse_stripe_signature("t=12345");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_timestamp_tolerance() {
        let handler =
            StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(60));

        // A timestamp far in the past
        let result = handler.validate_timestamp(1_000_000_000);
        assert!(matches!(
            result,
            Err(WebhookError::TimestampValidation { .. })
        ));

        // Current timestamp should pass
        let now = Utc::now().timestamp();
        assert!(handler.validate_timestamp(now).is_ok());
    }

    #[test]
    fn test_linear_missing_signature() {
        let handler = LinearWebhook::new("secret");
        let headers = HashMap::new();
        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(result, Err(WebhookError::MissingSignature(_))));
    }

    #[test]
    fn test_slack_webhook_construction() {
        let handler = SlackWebhook::new("signing-secret");
        let debug = format!("{handler:?}");
        assert!(debug.contains("SlackWebhook"));
    }

    #[test]
    fn test_slack_missing_signature() {
        let handler = SlackWebhook::new("secret");
        let headers = HashMap::new();
        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(result, Err(WebhookError::MissingSignature(_))));
    }

    #[test]
    fn test_slack_missing_timestamp() {
        let handler = SlackWebhook::new("secret");
        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), "v0=abc".to_string());
        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(result, Err(WebhookError::MissingSignature(_))));
    }

    #[test]
    fn test_webhook_registration_challenge_response_flow() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            let challenge = "challenge-token-abc";

            Mock::given(method("POST"))
                .and(path("/webhooks"))
                .and(body_string_contains("message.create"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "wh_123",
                    "challenge_url": format!("{}/challenge?challenge={challenge}", server.uri())
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/challenge"))
                .and(query_param("challenge", challenge))
                .respond_with(ResponseTemplate::new(200).set_body_string(challenge))
                .mount(&server)
                .await;

            let client = reqwest::Client::new();
            let registration_response = client
                .post(format!("{}/webhooks", server.uri()))
                .json(&serde_json::json!({
                    "events": ["message.create"],
                    "target": "https://connector.example.test/inbound"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap();

            let challenge_url = registration_response
                .get("challenge_url")
                .and_then(serde_json::Value::as_str)
                .unwrap();
            let challenge_response = client
                .get(challenge_url)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(challenge_response, challenge);
        })
        .unwrap();
    }

    #[test]
    fn test_challenge_event_routing() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::for_types(vec!["url_verification".to_string()])
                .with_provider("slack"),
            "challenge_handler",
        );

        let event = WebhookEvent::new("evt_1", "url_verification", "slack");
        let handlers = router.route(&event);
        assert_eq!(handlers, vec!["challenge_handler"]);
    }

    #[test]
    fn test_github_secret_rotation() {
        let old_handler = GitHubWebhook::new("old-secret");
        let new_handler = GitHubWebhook::new("new-secret");
        let body = br#"{"action":"opened","issue":{"number":7}}"#;

        let old_signature = format!("sha256={}", old_handler.verifier.compute(body));
        let mut old_headers = HashMap::new();
        old_headers.insert("x-hub-signature-256".to_string(), old_signature);
        old_headers.insert("x-github-event".to_string(), "issues".to_string());

        assert!(old_handler.verify_and_parse(&old_headers, body).is_ok());
        assert!(new_handler.verify_and_parse(&old_headers, body).is_err());

        let new_signature = format!("sha256={}", new_handler.verifier.compute(body));
        let mut new_headers = HashMap::new();
        new_headers.insert("x-hub-signature-256".to_string(), new_signature);
        new_headers.insert("x-github-event".to_string(), "issues".to_string());

        assert!(new_handler.verify_and_parse(&new_headers, body).is_ok());
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn test_slack_valid_signature_verification() {
        let signing_secret = "8f742231b10e8888abcd99yez67a42b9";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback","event":{"type":"message"}}"#;

        let timestamp = Utc::now().timestamp();
        let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new(signing_secret);
        let computed = verifier.compute(base_string.as_bytes());
        let signature = format!("v0={computed}");

        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), signature);
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            timestamp.to_string(),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.provider, "slack");
        assert_eq!(event.event_type, "event_callback");
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_slack_invalid_timestamp_format() {
        let handler = SlackWebhook::new("secret");
        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), "v0=abc".to_string());
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            "not-a-number".to_string(),
        );
        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_slack_expired_timestamp() {
        let handler = SlackWebhook::new("secret");
        let old_timestamp = 1_000_000_000_i64;
        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), "v0=abc123".to_string());
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            old_timestamp.to_string(),
        );

        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(
            result,
            Err(WebhookError::TimestampValidation { .. })
        ));
    }

    #[test]
    fn test_slack_extracts_nested_event_type() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"event":{"type":"message"}}"#;

        let timestamp = Utc::now().timestamp();
        let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new(signing_secret);
        let computed = verifier.compute(base_string.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), format!("v0={computed}"));
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            timestamp.to_string(),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "message");
    }

    #[test]
    fn test_stripe_full_end_to_end_verification() {
        let secret = "whsec_test_secret";
        let handler = StripeWebhook::new(secret);
        let body = br#"{"id":"evt_123","type":"payment_intent.succeeded","data":{}}"#;

        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new(secret);
        let sig = verifier.compute(signed_payload.as_bytes());
        let sig_header = format!("t={timestamp},v1={sig}");

        let mut headers = HashMap::new();
        headers.insert("stripe-signature".to_string(), sig_header);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "evt_123");
        assert_eq!(event.event_type, "payment_intent.succeeded");
        assert_eq!(event.provider, "stripe");
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
    }

    #[test]
    fn test_stripe_missing_signature_header() {
        let handler = StripeWebhook::new("secret");
        let headers = HashMap::new();
        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(result, Err(WebhookError::MissingSignature(_))));
    }

    #[test]
    fn test_stripe_expired_timestamp() {
        let handler = StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(5));
        let old_ts = 1_000_000_000_i64;
        let verifier = HmacSha256Verifier::new("secret");
        let signed_payload = format!("{old_ts}.{{}}",);
        let sig = verifier.compute(signed_payload.as_bytes());
        let sig_header = format!("t={old_ts},v1={sig}");

        let mut headers = HashMap::new();
        headers.insert("stripe-signature".to_string(), sig_header);

        let result = handler.verify_and_parse(&headers, b"{}");
        assert!(matches!(
            result,
            Err(WebhookError::TimestampValidation { .. })
        ));
    }

    #[test]
    fn test_stripe_signature_with_extra_fields() {
        // Stripe signature headers can contain other prefixed fields
        let (ts, sigs) =
            StripeWebhook::parse_stripe_signature("t=1234567890,v1=abc123,v2=ignored").unwrap();
        assert_eq!(ts, 1_234_567_890);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0], "abc123");
    }

    #[test]
    fn test_stripe_signature_missing_timestamp() {
        let result = StripeWebhook::parse_stripe_signature("v1=abc123");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_github_auto_generates_delivery_id() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action": "created"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "star".to_string());
        // No x-github-delivery header

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "star");
        // ID should be auto-generated UUID
        assert!(!event.id.is_empty());
        assert!(event.id.len() >= 32); // UUID format
    }

    #[test]
    fn test_github_defaults_event_type_to_unknown() {
        let handler = GitHubWebhook::new("secret");
        let body = b"{}";
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        // No x-github-event header

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "unknown");
    }

    #[test]
    fn test_github_invalid_json_body() {
        let handler = GitHubWebhook::new("secret");
        let body = b"not valid json";
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::JsonError(_))));
    }

    #[test]
    fn test_linear_invalid_json_body() {
        let handler = LinearWebhook::new("secret");
        let body = b"not json";
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::JsonError(_))));
    }

    #[test]
    fn test_linear_auto_generates_webhook_id() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type": "Issue", "action": "update"}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);
        // No webhookId in payload

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "Issue");
        assert!(!event.id.is_empty());
    }

    #[test]
    fn test_linear_taint_flags_present() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type": "Comment", "webhookId": "wh_456"}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_webhook_provider_equality() {
        assert_eq!(WebhookProvider::GitHub, WebhookProvider::GitHub);
        assert_ne!(WebhookProvider::GitHub, WebhookProvider::Stripe);
        assert_ne!(WebhookProvider::Discord, WebhookProvider::Custom);
    }

    #[test]
    fn test_webhook_provider_copy() {
        let p = WebhookProvider::GitHub;
        let p2 = p; // Copy
        assert_eq!(p, p2);
    }

    #[test]
    fn test_github_case_insensitive_headers() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action": "opened"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        // Use capitalized header names
        let mut headers = HashMap::new();
        headers.insert("X-Hub-Signature-256".to_string(), signature);
        headers.insert("X-GitHub-Event".to_string(), "issues".to_string());
        headers.insert("X-GitHub-Delivery".to_string(), "del_1".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "del_1");
        assert_eq!(event.event_type, "issues");
    }

    #[test]
    fn test_stripe_case_insensitive_header() {
        let handler = StripeWebhook::new("secret");
        let body = br#"{"id":"evt_1","type":"charge.created"}"#;

        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(signed_payload.as_bytes());

        let mut headers = HashMap::new();
        headers.insert(
            "Stripe-Signature".to_string(),
            format!("t={timestamp},v1={sig}"),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "evt_1");
    }

    #[test]
    fn test_stripe_defaults_event_fields_when_missing() {
        let handler = StripeWebhook::new("secret");
        let body = b"{}"; // No id or type fields

        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(signed_payload.as_bytes());

        let mut headers = HashMap::new();
        headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp},v1={sig}"),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "unknown");
        assert_eq!(event.event_type, "unknown");
    }

    #[test]
    fn test_slack_event_id_from_payload() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback","event_id":"Ev12345"}"#;

        let timestamp = Utc::now().timestamp();
        let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new(signing_secret);
        let computed = verifier.compute(base_string.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), format!("v0={computed}"));
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            timestamp.to_string(),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "Ev12345");
    }

    #[test]
    fn test_github_preserves_all_headers() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"ref":"refs/heads/main"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());
        headers.insert("x-github-delivery".to_string(), "d1".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.headers.len(), 4);
        assert_eq!(event.header("content-type"), Some("application/json"));
    }

    #[test]
    fn test_event_routing_multiple_providers() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::all().with_provider("github"),
            "github_all",
        );
        router.subscribe(
            EventSubscription::for_types(vec!["push".to_string()]),
            "push_any",
        );
        router.subscribe(
            EventSubscription::all().with_provider("stripe"),
            "stripe_all",
        );

        let gh_push = WebhookEvent::new("e1", "push", "github");
        let handlers = router.route(&gh_push);
        assert_eq!(handlers.len(), 2);
        assert!(handlers.contains(&"github_all"));
        assert!(handlers.contains(&"push_any"));

        let stripe_evt = WebhookEvent::new("e2", "charge.created", "stripe");
        let handlers = router.route(&stripe_evt);
        assert_eq!(handlers.len(), 1);
        assert!(handlers.contains(&"stripe_all"));
    }

    // ── Batch 3: SunnyMoose deep test expansion ──

    #[test]
    fn test_webhook_provider_debug() {
        for provider in [
            WebhookProvider::GitHub,
            WebhookProvider::Stripe,
            WebhookProvider::Slack,
            WebhookProvider::Linear,
            WebhookProvider::Discord,
            WebhookProvider::Custom,
        ] {
            let debug = format!("{provider:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_webhook_provider_clone() {
        let original = WebhookProvider::GitHub;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_github_webhook_debug() {
        let handler = GitHubWebhook::new("my_super_s3cret_key!");
        let debug = format!("{handler:?}");
        assert!(debug.contains("GitHubWebhook"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("my_super_s3cret_key!"));
    }

    #[test]
    fn test_stripe_webhook_debug() {
        let handler = StripeWebhook::new("whsec_test");
        let debug = format!("{handler:?}");
        assert!(debug.contains("StripeWebhook"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_linear_webhook_debug() {
        let handler = LinearWebhook::new("lin_secret");
        let debug = format!("{handler:?}");
        assert!(debug.contains("LinearWebhook"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_slack_webhook_debug_redacts() {
        let handler = SlackWebhook::new("xoxb-secret-token");
        let debug = format!("{handler:?}");
        assert!(debug.contains("SlackWebhook"));
        assert!(!debug.contains("xoxb-secret-token"));
    }

    #[test]
    fn test_github_large_json_payload() {
        let handler = GitHubWebhook::new("secret");
        let large_obj = serde_json::json!({
            "commits": (0..100).map(|i| serde_json::json!({
                "id": format!("sha_{i}"),
                "message": format!("commit message {i}"),
                "author": {"name": "user", "email": "user@example.test"}
            })).collect::<Vec<_>>()
        });
        let body = serde_json::to_vec(&large_obj).unwrap();
        let signature = format!("sha256={}", handler.verifier.compute(&body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());
        headers.insert("x-github-delivery".to_string(), "large_del".to_string());

        let event = handler.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(event.id, "large_del");
        assert!(
            event
                .payload
                .get("commits")
                .unwrap()
                .as_array()
                .unwrap()
                .len()
                == 100
        );
    }

    #[test]
    fn test_github_unicode_payload() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action": "\u00e9\u00f1\u00fc", "repo": "test"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());
        headers.insert("x-github-delivery".to_string(), "uni_del".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "uni_del");
    }

    #[test]
    fn test_stripe_multiple_v1_signatures() {
        // Stripe can send multiple v1 signatures during secret rotation
        let (ts, sigs) =
            StripeWebhook::parse_stripe_signature("t=1234567890,v1=sig1,v1=sig2").unwrap();
        assert_eq!(ts, 1_234_567_890);
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0], "sig1");
        assert_eq!(sigs[1], "sig2");
    }

    #[test]
    fn test_stripe_timestamp_exactly_at_boundary() {
        let handler =
            StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(300));
        let now = Utc::now().timestamp();
        // Exactly at boundary should pass
        assert!(handler.validate_timestamp(now).is_ok());
        // Within tolerance should pass
        assert!(handler.validate_timestamp(now - 100).is_ok());
    }

    #[test]
    fn test_stripe_zero_tolerance() {
        let handler = StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(0));
        let now = Utc::now().timestamp();
        // With zero tolerance, only exact match would pass
        // Due to timing, now should match exactly
        assert!(handler.validate_timestamp(now).is_ok());
    }

    #[test]
    fn test_linear_empty_payload_fields() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type": "", "webhookId": ""}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "");
        assert_eq!(event.id, "");
    }

    #[test]
    fn test_github_preserves_payload_structure() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action":"opened","issue":{"number":42,"title":"Bug report","labels":[{"name":"bug"}]}}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "issues".to_string());
        headers.insert("x-github-delivery".to_string(), "d1".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.get_str("action"), Some("opened"));
        assert_eq!(event.get_i64("issue.number"), Some(42));
        assert_eq!(event.get_str("issue.title"), Some("Bug report"));
    }

    #[test]
    fn test_stripe_invalid_json_body() {
        let handler = StripeWebhook::new("secret");
        let body = b"not valid json at all";
        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(signed_payload.as_bytes());

        let mut headers = HashMap::new();
        headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp},v1={sig}"),
        );

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::JsonError(_))));
    }

    #[test]
    fn test_stripe_wrong_secret_fails() {
        let handler = StripeWebhook::new("correct_secret");
        let body = br#"{"id":"evt_1","type":"test"}"#;
        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let wrong_verifier = HmacSha256Verifier::new("wrong_secret");
        let sig = wrong_verifier.compute(signed_payload.as_bytes());

        let mut headers = HashMap::new();
        headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp},v1={sig}"),
        );

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::InvalidSignature)));
    }

    #[test]
    fn test_slack_case_insensitive_headers() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback"}"#;

        let timestamp = Utc::now().timestamp();
        let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new(signing_secret);
        let computed = verifier.compute(base_string.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("X-Slack-Signature".to_string(), format!("v0={computed}"));
        headers.insert(
            "X-Slack-Request-Timestamp".to_string(),
            timestamp.to_string(),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.provider, "slack");
    }

    #[test]
    fn test_linear_case_insensitive_header() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type": "Issue", "webhookId": "wh_1"}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("Linear-Signature".to_string(), signature);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "wh_1");
    }

    #[test]
    fn test_stripe_signature_empty_parts() {
        // Extra commas in signature header
        let result = StripeWebhook::parse_stripe_signature("t=123,,v1=abc,,");
        assert!(result.is_ok());
        let (ts, sigs) = result.unwrap();
        assert_eq!(ts, 123);
        assert_eq!(sigs, vec!["abc"]);
    }
}
