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
        let (timestamp, signature) = self.parse_stripe_signature(signature_header)?;

        // Validate timestamp
        self.validate_timestamp(timestamp)?;

        // Build signed payload (Stripe format: timestamp.body)
        let timestamp_str = timestamp.to_string();
        let mut signed_payload = timestamp_str.as_bytes().to_vec();
        signed_payload.push(b'.');
        signed_payload.extend_from_slice(body);

        // Verify signature
        self.verifier.verify(&signed_payload, &signature)?;

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
            .with_payload(payload)
            .with_headers(headers.clone()))
    }

    /// Parse Stripe signature header.
    fn parse_stripe_signature(&self, header: &str) -> WebhookResult<(i64, String)> {
        let mut timestamp = None;
        let mut signature = None;

        for part in header.split(',') {
            if let Some(ts) = part.strip_prefix("t=") {
                timestamp = ts.parse().ok();
            } else if let Some(sig) = part.strip_prefix("v1=") {
                signature = Some(sig.to_string());
            }
        }

        match (timestamp, signature) {
            (Some(ts), Some(sig)) => Ok((ts, sig)),
            _ => Err(WebhookError::InvalidPayload(
                "Invalid Stripe-Signature format".into(),
            )),
        }
    }

    /// Validate timestamp is within tolerance.
    fn validate_timestamp(&self, timestamp: i64) -> WebhookResult<()> {
        let now = Utc::now().timestamp();
        let tolerance = self.timestamp_tolerance.as_secs() as i64;

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
        if (now - timestamp).abs() > self.timestamp_tolerance.as_secs() as i64 {
            return Err(WebhookError::TimestampValidation {
                reason: "Timestamp outside tolerance".into(),
                timestamp: Some(timestamp),
                current_time: now,
                tolerance: self.timestamp_tolerance,
            });
        }

        // Build Slack signature base string
        let base_string = format!("v0:{}:{}", timestamp, String::from_utf8_lossy(body));

        // Verify signature
        self.verifier.verify(base_string.as_bytes(), signature)?;

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
            .with_payload(payload)
            .with_headers(headers.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_stripe_signature_parsing() {
        let handler = StripeWebhook::new("secret");

        let (ts, sig) = handler
            .parse_stripe_signature("t=1234567890,v1=abc123")
            .unwrap();

        assert_eq!(ts, 1_234_567_890);
        assert_eq!(sig, "abc123");
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
        let handler = StripeWebhook::new("secret");

        let result = handler.parse_stripe_signature("invalid-format");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_missing_v1() {
        let handler = StripeWebhook::new("secret");

        let result = handler.parse_stripe_signature("t=12345");
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
}
