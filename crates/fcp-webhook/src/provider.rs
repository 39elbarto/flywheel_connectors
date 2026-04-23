//! Provider-specific webhook handlers.
//!
//! Pre-configured handlers for common webhook providers.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    HmacSha256Verifier, SignatureVerifier, WebhookError, WebhookEvent, WebhookResult,
    default_max_payload_size, default_timestamp_tolerance,
};

/// Cap every Stripe `t=` timestamp value at this many characters before
/// we copy it into the signed-payload buffer. Unix seconds fit in 10
/// decimal digits until the year 2286, so 20 is ample for legitimate
/// traffic but keeps a malicious upstream from blowing up
/// `signed_payload.len()` with a multi-megabyte timestamp prefix.
const MAX_STRIPE_TIMESTAMP_LEN: usize = 20;

/// Cap every `v1=` signature string from the `Stripe-Signature` header
/// at this many characters. HMAC-SHA-256 in hex is 64 chars; the cap
/// leaves headroom for future wider-hash algorithms while rejecting
/// a 1 MB "v1" value that would allocate memory in `sig.to_string()`
/// before ever reaching the HMAC verifier.
const MAX_STRIPE_SIGNATURE_LEN: usize = 128;

/// Cap Slack's `X-Slack-Request-Timestamp` header before copying it into
/// the `v0:{timestamp}:{body}` HMAC base string. Unix seconds fit in 10
/// decimal digits until the year 2286, so 20 allows legitimate leading-zero
/// variants while fail-closing multi-megabyte attacker-controlled values.
const MAX_SLACK_TIMESTAMP_LEN: usize = 20;

fn validate_timestamp_with_reason(
    timestamp: i64,
    now: i64,
    tolerance: Duration,
    reason: &'static str,
) -> WebhookResult<()> {
    let tolerance_secs = tolerance.as_secs();
    let outside_window = if tolerance_secs == 0 {
        now.abs_diff(timestamp) != 0
    } else {
        now.abs_diff(timestamp) >= tolerance_secs
    };

    if outside_window {
        return Err(WebhookError::TimestampValidation {
            reason: reason.into(),
            timestamp: Some(timestamp),
            current_time: now,
            tolerance,
        });
    }

    Ok(())
}

fn header_value_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> WebhookResult<Option<&'a str>> {
    let mut matches = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str());
    let first = matches.next();
    if first.is_some() && matches.next().is_some() {
        return Err(WebhookError::InvalidPayload(format!(
            "duplicate {name} headers"
        )));
    }
    Ok(first)
}

fn deterministic_event_id(provider: &str, event_type: &str, body: &[u8]) -> String {
    deterministic_event_id_with_context(provider, event_type, body, None)
}

fn deterministic_event_id_with_context(
    provider: &str,
    event_type: &str,
    body: &[u8],
    context: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update([0]);
    hasher.update(event_type.as_bytes());
    hasher.update([0]);
    if let Some(context) = context {
        hasher.update(context.as_bytes());
    }
    hasher.update([0]);
    hasher.update(body);
    let digest = hasher.finalize();
    format!("{provider}:{}", hex::encode(digest))
}

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
///
/// # Replay protection
///
/// GitHub webhook deliveries do **not** carry a timestamp header, so
/// [`verify_and_parse`](Self::verify_and_parse) cannot enforce a replay
/// window the way Stripe's `Stripe-Signature` timestamp does. A captured
/// delivery remains valid forever for the lifetime of the shared HMAC
/// secret. Callers **must** enforce replay protection at a higher layer,
/// typically by feeding the `X-GitHub-Delivery` header (exposed as the
/// event `id` on the parsed [`WebhookEvent`]) into the idempotency
/// tracking offered by [`crate::WebhookHandler::check_replay`] /
/// [`crate::WebhookHandler::record_event`]. Signature verification
/// alone is not sufficient; treating it as sufficient allows an attacker
/// who captures one legitimate delivery to replay it against the
/// endpoint indefinitely.
#[derive(Debug)]
pub struct GitHubWebhook {
    verifier: HmacSha256Verifier,
    max_payload_size: usize,
}

impl GitHubWebhook {
    /// Create a new GitHub webhook handler.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(secret),
            max_payload_size: default_max_payload_size(),
        }
    }

    /// Override the maximum webhook body size this handler will verify
    /// or parse. Bodies larger than the limit are rejected with
    /// [`WebhookError::PayloadTooLarge`] before HMAC verification runs,
    /// so an attacker cannot amplify HMAC CPU cost or JSON parse memory
    /// by delivering an unbounded body.
    #[must_use]
    pub const fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
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
        // Bound body size before any HMAC or JSON work runs, so an
        // attacker cannot force the verifier to chew through an
        // unbounded payload.
        if body.len() > self.max_payload_size {
            return Err(WebhookError::PayloadTooLarge {
                size: body.len(),
                limit: self.max_payload_size,
            });
        }

        // Get signature header
        let signature = header_value_case_insensitive(headers, "x-hub-signature-256")?
            .ok_or_else(|| WebhookError::MissingSignature("X-Hub-Signature-256".into()))?;

        // Verify signature
        self.verifier.verify(body, signature)?;

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_type = header_value_case_insensitive(headers, "x-github-event")?
            .map_or_else(|| "unknown".to_string(), str::to_string);

        let delivery_id = header_value_case_insensitive(headers, "x-github-delivery")?
            .filter(|id| !id.is_empty())
            .map_or_else(
                || deterministic_event_id("github", &event_type, body),
                str::to_string,
            );

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
    max_payload_size: usize,
}

impl StripeWebhook {
    /// Create a new Stripe webhook handler.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(secret),
            timestamp_tolerance: default_timestamp_tolerance(),
            max_payload_size: default_max_payload_size(),
        }
    }

    /// Set timestamp tolerance.
    #[must_use]
    pub const fn with_timestamp_tolerance(mut self, tolerance: Duration) -> Self {
        self.timestamp_tolerance = tolerance;
        self
    }

    /// Override the maximum webhook body size this handler will verify
    /// or parse. Bodies larger than the limit are rejected with
    /// [`WebhookError::PayloadTooLarge`] before the timestamp check or
    /// HMAC verification runs.
    #[must_use]
    pub const fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
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
        // Bound body size before timestamp parsing or HMAC verification.
        // `verify_and_parse` internally builds `signed_payload` as
        // `timestamp_str + "." + body`, so a large body forces a second
        // allocation of similar size; reject early.
        if body.len() > self.max_payload_size {
            return Err(WebhookError::PayloadTooLarge {
                size: body.len(),
                limit: self.max_payload_size,
            });
        }

        // Get Stripe-Signature header
        let signature_header = header_value_case_insensitive(headers, "stripe-signature")?
            .ok_or_else(|| WebhookError::MissingSignature("Stripe-Signature".into()))?;

        // Parse signature header (format: t=timestamp,v1=signature)
        let (timestamp_str, timestamp, signatures) =
            Self::parse_stripe_signature(signature_header)?;

        // Validate timestamp
        self.validate_timestamp(timestamp)?;

        // Build signed payload (Stripe format: timestamp.body)
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
        let event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let event_id = payload.get("id").and_then(Value::as_str).map_or_else(
            || {
                deterministic_event_id_with_context(
                    "stripe",
                    &event_type,
                    body,
                    Some(timestamp_str.as_str()),
                )
            },
            ToString::to_string,
        );

        Ok(WebhookEvent::new(event_id, event_type, "stripe")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }

    /// Maximum number of `v1=` signatures accepted from a single header.
    const MAX_STRIPE_SIGNATURES: usize = 10;

    /// Parse Stripe signature header.
    fn parse_stripe_signature(header: &str) -> WebhookResult<(String, i64, Vec<String>)> {
        let mut timestamp = None;
        let mut signatures = Vec::new();

        for part in header.split(',') {
            let part = part.trim();
            if let Some(ts) = part.strip_prefix("t=") {
                // Cap timestamp length before `to_string()` so a
                // malicious upstream can't force a huge allocation
                // by sending a megabyte-long "t=" value. Anything
                // that fails `parse::<i64>()` is rejected below, but
                // the allocation happens first — bound it here.
                if ts.len() > MAX_STRIPE_TIMESTAMP_LEN {
                    return Err(WebhookError::InvalidPayload(
                        "Stripe-Signature timestamp exceeds maximum length".into(),
                    ));
                }
                if timestamp.is_some() {
                    return Err(WebhookError::InvalidPayload(
                        "Stripe-Signature contains multiple timestamp values".into(),
                    ));
                }
                timestamp = ts.parse().ok().map(|parsed| (ts.to_string(), parsed));
            } else if let Some(sig) = part.strip_prefix("v1=") {
                if signatures.len() >= Self::MAX_STRIPE_SIGNATURES {
                    return Err(WebhookError::InvalidPayload(
                        "too many signatures in Stripe-Signature header".into(),
                    ));
                }
                if sig.is_empty() {
                    return Err(WebhookError::InvalidPayload(
                        "Stripe-Signature v1 value must not be empty".into(),
                    ));
                }
                if sig.len() > MAX_STRIPE_SIGNATURE_LEN {
                    return Err(WebhookError::InvalidPayload(
                        "Stripe-Signature v1 value exceeds maximum length".into(),
                    ));
                }
                signatures.push(sig.to_string());
            }
        }

        if let Some((raw_timestamp, parsed_timestamp)) = timestamp {
            if !signatures.is_empty() {
                return Ok((raw_timestamp, parsed_timestamp, signatures));
            }
        }

        Err(WebhookError::InvalidPayload(
            "Invalid Stripe-Signature format".into(),
        ))
    }

    /// Validate timestamp is within tolerance.
    fn validate_timestamp(&self, timestamp: i64) -> WebhookResult<()> {
        self.validate_timestamp_at(timestamp, Utc::now().timestamp())
    }

    fn validate_timestamp_at(&self, timestamp: i64, now: i64) -> WebhookResult<()> {
        validate_timestamp_with_reason(
            timestamp,
            now,
            self.timestamp_tolerance,
            "Timestamp outside tolerance window",
        )
    }
}

/// Slack webhook handler.
#[derive(Debug)]
pub struct SlackWebhook {
    verifier: HmacSha256Verifier,
    timestamp_tolerance: Duration,
    max_payload_size: usize,
}

impl SlackWebhook {
    /// Create a new Slack webhook handler.
    #[must_use]
    pub fn new(signing_secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(signing_secret),
            timestamp_tolerance: default_timestamp_tolerance(),
            max_payload_size: default_max_payload_size(),
        }
    }

    /// Override the maximum webhook body size this handler will verify
    /// or parse. Bodies larger than the limit are rejected with
    /// [`WebhookError::PayloadTooLarge`] before timestamp parsing or
    /// HMAC verification runs. The Slack signing base string is
    /// `v0:{timestamp}:{body}`, so an unbounded body forces a second
    /// allocation of comparable size; reject early.
    #[must_use]
    pub const fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Override the timestamp tolerance window used for replay protection.
    #[must_use]
    pub const fn with_timestamp_tolerance(mut self, tolerance: Duration) -> Self {
        self.timestamp_tolerance = tolerance;
        self
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
        // Bound body size before timestamp parsing or HMAC verification.
        // The signing base string is built as `v0:{timestamp}:{body}`,
        // so a large body forces a second allocation of similar size.
        if body.len() > self.max_payload_size {
            return Err(WebhookError::PayloadTooLarge {
                size: body.len(),
                limit: self.max_payload_size,
            });
        }

        // Get headers
        let signature = header_value_case_insensitive(headers, "x-slack-signature")?
            .ok_or_else(|| WebhookError::MissingSignature("X-Slack-Signature".into()))?;

        let timestamp_str = header_value_case_insensitive(headers, "x-slack-request-timestamp")?
            .ok_or_else(|| WebhookError::MissingSignature("X-Slack-Request-Timestamp".into()))?;
        if timestamp_str.len() > MAX_SLACK_TIMESTAMP_LEN {
            return Err(WebhookError::InvalidPayload(
                "X-Slack-Request-Timestamp exceeds maximum length".into(),
            ));
        }

        let timestamp: i64 = timestamp_str
            .parse()
            .map_err(|_| WebhookError::InvalidPayload("Invalid timestamp".into()))?;

        // Validate timestamp
        self.validate_timestamp_at(timestamp, Utc::now().timestamp())?;

        // Build Slack signature base string
        let mut base_string = format!("v0:{timestamp_str}:").into_bytes();
        base_string.extend_from_slice(body);

        // Verify signature
        self.verifier.verify(&base_string, signature)?;

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_type = Self::event_type(&payload).to_string();
        let event_id = payload.get("event_id").and_then(Value::as_str).map_or_else(
            || deterministic_event_id_with_context("slack", &event_type, body, Some(timestamp_str)),
            ToString::to_string,
        );

        Ok(WebhookEvent::new(event_id, event_type, "slack")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }

    fn event_type(payload: &Value) -> &str {
        match payload.get("type").and_then(Value::as_str) {
            Some("event_callback") => payload
                .get("event")
                .and_then(|event| event.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            Some(top_level_type) => top_level_type,
            None => payload
                .get("event")
                .and_then(|event| event.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
        }
    }

    fn validate_timestamp_at(&self, timestamp: i64, now: i64) -> WebhookResult<()> {
        validate_timestamp_with_reason(
            timestamp,
            now,
            self.timestamp_tolerance,
            "Timestamp outside tolerance",
        )
    }
}

/// Linear webhook handler.
///
/// # Replay protection
///
/// Linear webhook deliveries do not carry a timestamp header that is
/// covered by the HMAC, so [`verify_and_parse`](Self::verify_and_parse)
/// cannot enforce a replay window the way Stripe's `Stripe-Signature`
/// timestamp does. A captured delivery remains valid forever for the
/// lifetime of the shared signing secret. Callers **must** enforce
/// replay protection at a higher layer, typically by feeding the parsed
/// event `id` (Linear's `webhookId`) into
/// [`crate::WebhookHandler::check_replay`] /
/// [`crate::WebhookHandler::record_event`]. Signature verification
/// alone is not sufficient.
#[derive(Debug)]
pub struct LinearWebhook {
    verifier: HmacSha256Verifier,
    max_payload_size: usize,
}

impl LinearWebhook {
    /// Create a new Linear webhook handler.
    #[must_use]
    pub fn new(signing_secret: impl AsRef<[u8]>) -> Self {
        Self {
            verifier: HmacSha256Verifier::new(signing_secret),
            max_payload_size: default_max_payload_size(),
        }
    }

    /// Override the maximum webhook body size this handler will verify
    /// or parse. Bodies larger than the limit are rejected with
    /// [`WebhookError::PayloadTooLarge`] before HMAC verification runs.
    #[must_use]
    pub const fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
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
        // Bound body size before any HMAC or JSON work runs, so an
        // attacker cannot force the verifier to chew through an
        // unbounded payload.
        if body.len() > self.max_payload_size {
            return Err(WebhookError::PayloadTooLarge {
                size: body.len(),
                limit: self.max_payload_size,
            });
        }

        // Get signature
        let signature = header_value_case_insensitive(headers, "linear-signature")?
            .ok_or_else(|| WebhookError::MissingSignature("Linear-Signature".into()))?;

        // Verify signature
        self.verifier.verify(body, signature)?;

        // Parse payload
        let payload: Value = serde_json::from_slice(body)?;

        // Extract event details
        let event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let event_id = payload
            .get("webhookId")
            .and_then(Value::as_str)
            .map_or_else(
                || deterministic_event_id("linear", &event_type, body),
                ToString::to_string,
            );

        Ok(WebhookEvent::new(event_id, event_type, "linear")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventRouter, EventSubscription, WebhookHandler};
    use fcp_core::TaintFlag;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ── Regression tests for audit findings ──

    #[test]
    fn github_rejects_oversized_body_before_verification() {
        // [HIGH] GitHubWebhook::verify_and_parse must cap body size before
        // running HMAC verification so an attacker cannot amplify CPU cost
        // with an unbounded payload.
        let handler = GitHubWebhook::new("secret").with_max_payload_size(64);
        let body = vec![b'x'; 128];

        let mut headers = HashMap::new();
        // A made-up signature header is fine — the size check must fire
        // *before* signature verification so we never reach the HMAC.
        headers.insert("x-hub-signature-256".into(), "sha256=deadbeef".into());
        headers.insert("x-github-event".into(), "push".into());

        match handler.verify_and_parse(&headers, &body) {
            Err(WebhookError::PayloadTooLarge { size, limit }) => {
                assert_eq!(size, 128);
                assert_eq!(limit, 64);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn stripe_rejects_oversized_body_before_signature_parse() {
        // [HIGH] Same guard on the Stripe handler: reject oversized
        // bodies before parsing the signature header or building the
        // signed_payload allocation.
        let handler = StripeWebhook::new("secret").with_max_payload_size(32);
        let body = vec![b'y'; 128];

        let mut headers = HashMap::new();
        headers.insert("stripe-signature".into(), "t=1700000000,v1=deadbeef".into());

        match handler.verify_and_parse(&headers, &body) {
            Err(WebhookError::PayloadTooLarge { size, limit }) => {
                assert_eq!(size, 128);
                assert_eq!(limit, 32);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn stripe_rejects_oversized_timestamp_value() {
        // [MEDIUM] parse_stripe_signature must cap the timestamp
        // string length before `to_string()` so a malicious upstream
        // cannot allocate an oversized raw_timestamp that later gets
        // prepended to the signed_payload.
        let huge_ts = "1".repeat(MAX_STRIPE_TIMESTAMP_LEN + 1);
        let header = format!("t={huge_ts},v1=abc");
        let err = StripeWebhook::parse_stripe_signature(&header).unwrap_err();
        match err {
            WebhookError::InvalidPayload(msg) => {
                assert!(
                    msg.contains("timestamp"),
                    "message should name the field: {msg}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    #[test]
    fn stripe_rejects_oversized_v1_value() {
        // [MEDIUM] Cap per-signature string length so 10 × huge v1
        // entries can't force 10× giant hex decodes.
        let huge_sig = "a".repeat(MAX_STRIPE_SIGNATURE_LEN + 1);
        let header = format!("t=1700000000,v1={huge_sig}");
        let err = StripeWebhook::parse_stripe_signature(&header).unwrap_err();
        match err {
            WebhookError::InvalidPayload(msg) => {
                assert!(
                    msg.contains("v1") || msg.contains("signature"),
                    "message should name the field: {msg}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    #[test]
    fn stripe_accepts_boundary_sized_timestamp_and_signature() {
        // Positive-side boundary: the exactly-at-limit values must
        // still parse (with a valid numeric timestamp).
        let ts = format!("0{}", i64::MAX);
        let sig = "a".repeat(MAX_STRIPE_SIGNATURE_LEN);
        let header = format!("t={ts},v1={sig}");
        // At-limit length still parses when the numeric value remains
        // in-range for i64.
        let (raw, _parsed, sigs) =
            StripeWebhook::parse_stripe_signature(&header).expect("at-limit must parse");
        assert_eq!(raw.len(), MAX_STRIPE_TIMESTAMP_LEN);
        assert_eq!(sigs, vec![sig]);
    }

    #[test]
    fn slack_rejects_oversized_body_before_signature_parse() {
        // [MEDIUM] Same guard on the Slack handler: reject oversized
        // bodies before parsing the signature header or building the
        // `v0:{ts}:{body}` base-string allocation.
        let handler = SlackWebhook::new("secret").with_max_payload_size(32);
        let body = vec![b'z'; 128];

        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".into(), "v0=deadbeef".into());
        headers.insert("x-slack-request-timestamp".into(), "1700000000".into());

        match handler.verify_and_parse(&headers, &body) {
            Err(WebhookError::PayloadTooLarge { size, limit }) => {
                assert_eq!(size, 128);
                assert_eq!(limit, 32);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn linear_rejects_oversized_body_before_verification() {
        // [MEDIUM] LinearWebhook::verify_and_parse must cap body size
        // before running HMAC verification so an attacker cannot
        // amplify CPU cost with an unbounded payload.
        let handler = LinearWebhook::new("secret").with_max_payload_size(64);
        let body = vec![b'q'; 128];

        let mut headers = HashMap::new();
        headers.insert("linear-signature".into(), "deadbeef".into());

        match handler.verify_and_parse(&headers, &body) {
            Err(WebhookError::PayloadTooLarge { size, limit }) => {
                assert_eq!(size, 128);
                assert_eq!(limit, 64);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

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
        let (raw_ts, ts, sigs) =
            StripeWebhook::parse_stripe_signature("t=1234567890,v1=abc123").unwrap();

        assert_eq!(raw_ts, "1234567890");
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

    #[test]
    fn test_webhook_registration_routing_and_secret_rotation_lifecycle() {
        fcp_async_core::runtime::block_on_sync(async {
            let server = MockServer::start().await;
            let challenge = "challenge-token-lifecycle";

            Mock::given(method("POST"))
                .and(path("/github/webhooks"))
                .and(body_string_contains("issues"))
                .and(body_string_contains(
                    "https://connector.example.test/github",
                ))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "wh_lifecycle",
                    "challenge_url": format!(
                        "{}/github/challenge?challenge={challenge}",
                        server.uri()
                    ),
                    "secret_version": 2
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/github/challenge"))
                .and(query_param("challenge", challenge))
                .respond_with(ResponseTemplate::new(200).set_body_string(challenge))
                .mount(&server)
                .await;

            let client = reqwest::Client::new();
            let registration = client
                .post(format!("{}/github/webhooks", server.uri()))
                .json(&serde_json::json!({
                    "events": ["issues"],
                    "target": "https://connector.example.test/github"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap();
            assert_eq!(registration["id"], "wh_lifecycle");
            assert_eq!(registration["secret_version"], 2);

            let challenge_url = registration["challenge_url"].as_str().unwrap();
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

            let mut router = EventRouter::new();
            router.subscribe(
                EventSubscription::for_types(vec!["issues".to_string()]).with_provider("github"),
                "github_issue_handler",
            );

            let old_handler = GitHubWebhook::new("old-secret");
            let new_handler = GitHubWebhook::new("new-secret");
            let body =
                br#"{"action":"opened","issue":{"number":7,"title":"Lifecycle regression"}}"#;

            let old_signature = format!("sha256={}", old_handler.verifier.compute(body));
            let mut old_headers = HashMap::new();
            old_headers.insert("x-hub-signature-256".to_string(), old_signature);
            old_headers.insert("x-github-event".to_string(), "issues".to_string());
            old_headers.insert("x-github-delivery".to_string(), "delivery-old".to_string());

            let old_event = old_handler.verify_and_parse(&old_headers, body).unwrap();
            assert_eq!(old_event.id, "delivery-old");
            assert_eq!(old_event.payload["issue"]["title"], "Lifecycle regression");
            assert_eq!(router.route(&old_event), vec!["github_issue_handler"]);
            assert!(new_handler.verify_and_parse(&old_headers, body).is_err());

            let new_signature = format!("sha256={}", new_handler.verifier.compute(body));
            let mut new_headers = HashMap::new();
            new_headers.insert("x-hub-signature-256".to_string(), new_signature);
            new_headers.insert("x-github-event".to_string(), "issues".to_string());
            new_headers.insert("x-github-delivery".to_string(), "delivery-new".to_string());

            let new_event = new_handler.verify_and_parse(&new_headers, body).unwrap();
            assert_eq!(new_event.id, "delivery-new");
            assert_eq!(new_event.event_type, "issues");
            assert_eq!(router.route(&new_event), vec!["github_issue_handler"]);
        })
        .unwrap();
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
        assert_eq!(event.event_type, "message");
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
    fn test_slack_rejects_oversized_timestamp_value() {
        let handler = SlackWebhook::new("secret");
        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), "v0=abc".to_string());
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            "0".repeat(MAX_SLACK_TIMESTAMP_LEN + 1),
        );

        let err = handler.verify_and_parse(&headers, b"{}").unwrap_err();
        match err {
            WebhookError::InvalidPayload(msg) => {
                assert!(
                    msg.contains("X-Slack-Request-Timestamp"),
                    "message should name the bounded field: {msg}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
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
    fn test_slack_timestamp_exactly_at_boundary_rejected() {
        let handler =
            SlackWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(300));
        let now = 1_700_000_000_i64;
        assert!(matches!(
            handler.validate_timestamp_at(now - 300, now),
            Err(WebhookError::TimestampValidation { .. })
        ));
        assert!(handler.validate_timestamp_at(now - 299, now).is_ok());
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
    fn test_slack_preserves_top_level_control_event_type() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"url_verification","challenge":"abc"}"#;

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
        assert_eq!(event.event_type, "url_verification");
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
        let (raw_ts, ts, sigs) =
            StripeWebhook::parse_stripe_signature("t=1234567890,v1=abc123,v2=ignored").unwrap();
        assert_eq!(raw_ts, "1234567890");
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
    fn test_github_missing_delivery_uses_deterministic_fallback_id() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action": "created"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "star".to_string());
        // No x-github-delivery header

        let first = handler.verify_and_parse(&headers, body).unwrap();
        let second = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(first.event_type, "star");
        assert_eq!(first.id, deterministic_event_id("github", "star", body));
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn test_github_missing_delivery_fallback_distinguishes_event_headers() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action": "created"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut star_headers = HashMap::new();
        star_headers.insert("x-hub-signature-256".to_string(), signature.clone());
        star_headers.insert("x-github-event".to_string(), "star".to_string());

        let mut watch_headers = HashMap::new();
        watch_headers.insert("x-hub-signature-256".to_string(), signature);
        watch_headers.insert("x-github-event".to_string(), "watch".to_string());

        let star_event = handler.verify_and_parse(&star_headers, body).unwrap();
        let watch_event = handler.verify_and_parse(&watch_headers, body).unwrap();

        assert_eq!(
            star_event.id,
            deterministic_event_id("github", "star", body)
        );
        assert_eq!(
            watch_event.id,
            deterministic_event_id("github", "watch", body)
        );
        assert_ne!(star_event.id, watch_event.id);
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
    fn test_linear_missing_webhook_id_uses_deterministic_fallback_id() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type": "Issue", "action": "update"}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);
        // No webhookId in payload

        let first = handler.verify_and_parse(&headers, body).unwrap();
        let second = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(first.event_type, "Issue");
        assert_eq!(first.id, deterministic_event_id("linear", "Issue", body));
        assert_eq!(first.id, second.id);
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
        headers.insert("X-HUB-SIGNATURE-256".to_string(), signature);
        headers.insert("X-GITHUB-EVENT".to_string(), "issues".to_string());
        headers.insert("X-GITHUB-DELIVERY".to_string(), "del_1".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "del_1");
        assert_eq!(event.event_type, "issues");
    }

    #[test]
    fn test_github_duplicate_case_insensitive_signature_headers_rejected() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action": "opened"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("X-HUB-SIGNATURE-256".to_string(), signature.clone());
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("X-GITHUB-EVENT".to_string(), "issues".to_string());
        headers.insert("X-GITHUB-DELIVERY".to_string(), "del_dup".to_string());

        let err = handler
            .verify_and_parse(&headers, body)
            .expect_err("duplicate case-insensitive signature headers must be rejected");
        assert!(matches!(err, WebhookError::InvalidPayload(_)));
        assert!(
            err.to_string()
                .contains("duplicate x-hub-signature-256 headers"),
            "unexpected error: {err}"
        );
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
            "STRIPE-SIGNATURE".to_string(),
            format!("t={timestamp},v1={sig}"),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "evt_1");
    }

    #[test]
    fn test_stripe_duplicate_case_insensitive_signature_headers_rejected() {
        let handler = StripeWebhook::new("secret");
        let body = br#"{"id":"evt_dup","type":"charge.created"}"#;

        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let sig = HmacSha256Verifier::new("secret").compute(signed_payload.as_bytes());

        let mut headers = HashMap::new();
        let signature_header = format!("t={timestamp},v1={sig}");
        headers.insert("STRIPE-SIGNATURE".to_string(), signature_header.clone());
        headers.insert("stripe-signature".to_string(), signature_header);

        let err = handler
            .verify_and_parse(&headers, body)
            .expect_err("duplicate case-insensitive stripe headers must be rejected");
        assert!(matches!(err, WebhookError::InvalidPayload(_)));
        assert!(
            err.to_string()
                .contains("duplicate stripe-signature headers"),
            "unexpected error: {err}"
        );
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
        assert_eq!(
            event.id,
            deterministic_event_id_with_context(
                "stripe",
                "unknown",
                body,
                Some(&timestamp.to_string())
            )
        );
        assert_eq!(event.event_type, "unknown");
    }

    #[test]
    fn test_stripe_missing_event_id_uses_deterministic_fallback_without_aliasing_distinct_payloads()
    {
        let secret = "secret";
        let stripe = StripeWebhook::new(secret);
        let handler = WebhookHandler::new(HmacSha256Verifier::new(secret), "stripe");

        let first_body = br#"{"type":"charge.created","data":{"object":{"amount":1000}}}"#;
        let second_body = br#"{"type":"charge.created","data":{"object":{"amount":2000}}}"#;
        let timestamp = Utc::now().timestamp();
        let verifier = HmacSha256Verifier::new(secret);

        let first_signature = verifier
            .compute(format!("{timestamp}.{}", String::from_utf8_lossy(first_body)).as_bytes());
        let second_signature = verifier
            .compute(format!("{timestamp}.{}", String::from_utf8_lossy(second_body)).as_bytes());

        let mut first_headers = HashMap::new();
        first_headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp},v1={first_signature}"),
        );

        let mut second_headers = HashMap::new();
        second_headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp},v1={second_signature}"),
        );

        let first_event = stripe.verify_and_parse(&first_headers, first_body).unwrap();
        let second_event = stripe
            .verify_and_parse(&second_headers, second_body)
            .unwrap();

        assert_eq!(
            first_event.id,
            deterministic_event_id_with_context(
                "stripe",
                "charge.created",
                first_body,
                Some(&timestamp.to_string())
            )
        );
        assert_eq!(
            second_event.id,
            deterministic_event_id_with_context(
                "stripe",
                "charge.created",
                second_body,
                Some(&timestamp.to_string())
            )
        );
        assert_ne!(first_event.id, second_event.id);
        assert!(handler.claim_event(&first_event.id).is_ok());
        assert!(handler.claim_event(&second_event.id).is_ok());
    }

    #[test]
    fn test_stripe_missing_event_id_does_not_alias_same_payload_across_timestamps() {
        let secret = "secret";
        let stripe = StripeWebhook::new(secret);
        let body = br#"{"type":"charge.created"}"#;
        let verifier = HmacSha256Verifier::new(secret);

        let first_timestamp = Utc::now().timestamp();
        let second_timestamp = first_timestamp + 1;

        let first_signature = verifier
            .compute(format!("{first_timestamp}.{}", String::from_utf8_lossy(body)).as_bytes());
        let second_signature = verifier
            .compute(format!("{second_timestamp}.{}", String::from_utf8_lossy(body)).as_bytes());

        let mut first_headers = HashMap::new();
        first_headers.insert(
            "stripe-signature".to_string(),
            format!("t={first_timestamp},v1={first_signature}"),
        );

        let mut second_headers = HashMap::new();
        second_headers.insert(
            "stripe-signature".to_string(),
            format!("t={second_timestamp},v1={second_signature}"),
        );

        let first_event = stripe.verify_and_parse(&first_headers, body).unwrap();
        let second_event = stripe.verify_and_parse(&second_headers, body).unwrap();

        assert_ne!(first_event.id, second_event.id);
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
        let (raw_ts, ts, sigs) =
            StripeWebhook::parse_stripe_signature("t=1234567890,v1=sig1,v1=sig2").unwrap();
        assert_eq!(raw_ts, "1234567890");
        assert_eq!(ts, 1_234_567_890);
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0], "sig1");
        assert_eq!(sigs[1], "sig2");
    }

    #[test]
    fn test_stripe_parse_signature_rejects_excessive_v1_signatures() {
        // Build a header with MAX_STRIPE_SIGNATURES + 1 v1= entries.
        let sigs: Vec<String> = (0..=StripeWebhook::MAX_STRIPE_SIGNATURES)
            .map(|i| format!("v1=sig{i}"))
            .collect();
        let header = format!("t=1234567890,{}", sigs.join(","));
        let result = StripeWebhook::parse_stripe_signature(&header);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("too many signatures"),
            "expected 'too many signatures' error, got: {msg}",
        );
    }

    #[test]
    fn test_stripe_parse_signature_accepts_max_v1_signatures() {
        // Exactly MAX_STRIPE_SIGNATURES should succeed.
        let sigs: Vec<String> = (0..StripeWebhook::MAX_STRIPE_SIGNATURES)
            .map(|i| format!("v1=sig{i}"))
            .collect();
        let header = format!("t=1234567890,{}", sigs.join(","));
        let (_, _, parsed) = StripeWebhook::parse_stripe_signature(&header).unwrap();
        assert_eq!(parsed.len(), StripeWebhook::MAX_STRIPE_SIGNATURES);
    }

    #[test]
    fn test_stripe_timestamp_exactly_at_boundary() {
        let handler =
            StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(300));
        let now = 1_700_000_000_i64;
        // Exact replay-window boundary must fail closed.
        assert!(matches!(
            handler.validate_timestamp_at(now - 300, now),
            Err(WebhookError::TimestampValidation { .. })
        ));
        // Within tolerance should pass
        assert!(handler.validate_timestamp_at(now - 100, now).is_ok());
    }

    #[test]
    fn test_stripe_zero_tolerance() {
        let handler = StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(0));
        let now = 1_700_000_000_i64;
        // With zero tolerance, only exact match passes.
        assert!(handler.validate_timestamp_at(now, now).is_ok());
        assert!(matches!(
            handler.validate_timestamp_at(now - 1, now),
            Err(WebhookError::TimestampValidation { .. })
        ));
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
        headers.insert("X-SLACK-SIGNATURE".to_string(), format!("v0={computed}"));
        headers.insert(
            "X-SLACK-REQUEST-TIMESTAMP".to_string(),
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
        headers.insert("LINEAR-SIGNATURE".to_string(), signature);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "wh_1");
    }

    #[test]
    fn test_stripe_signature_empty_parts() {
        // Extra commas in signature header
        let result = StripeWebhook::parse_stripe_signature("t=123,,v1=abc,,");
        assert!(result.is_ok());
        let (raw_ts, ts, sigs) = result.unwrap();
        assert_eq!(raw_ts, "123");
        assert_eq!(ts, 123);
        assert_eq!(sigs, vec!["abc"]);
    }

    // ── Batch 4: SunnyMoose additional test expansion ──

    #[test]
    fn test_github_empty_body_valid_json() {
        let handler = GitHubWebhook::new("secret");
        let body = b"{}";
        let signature = format!("sha256={}", handler.verifier.compute(body));
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "ping".to_string());
        headers.insert("x-github-delivery".to_string(), "d1".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "d1");
        assert_eq!(event.event_type, "ping");
        assert_eq!(event.payload, serde_json::json!({}));
    }

    #[test]
    fn test_github_array_body() {
        let handler = GitHubWebhook::new("secret");
        let body = b"[1,2,3]";
        let signature = format!("sha256={}", handler.verifier.compute(body));
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());
        headers.insert("x-github-delivery".to_string(), "d2".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert!(event.payload.is_array());
    }

    #[test]
    fn test_stripe_parse_signature_only_timestamp_no_sig() {
        let result = StripeWebhook::parse_stripe_signature("t=999");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_parse_signature_only_sig_no_timestamp() {
        let result = StripeWebhook::parse_stripe_signature("v1=abc");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_parse_signature_empty_string() {
        let result = StripeWebhook::parse_stripe_signature("");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_parse_signature_non_numeric_timestamp() {
        let result = StripeWebhook::parse_stripe_signature("t=abc,v1=sig");
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_stripe_validate_timestamp_current() {
        let handler = StripeWebhook::new("secret");
        let now = Utc::now().timestamp();
        assert!(handler.validate_timestamp(now).is_ok());
    }

    #[test]
    fn test_stripe_validate_timestamp_far_future() {
        let handler =
            StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(60));
        let far_future = Utc::now().timestamp() + 1_000_000;
        assert!(matches!(
            handler.validate_timestamp(far_future),
            Err(WebhookError::TimestampValidation { .. })
        ));
    }

    #[test]
    fn test_stripe_validate_timestamp_within_tolerance() {
        let handler =
            StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(300));
        let recent = Utc::now().timestamp() - 100;
        assert!(handler.validate_timestamp(recent).is_ok());
    }

    #[test]
    fn test_linear_invalid_signature() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type":"Issue"}"#;
        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), "deadbeef".to_string());
        let result = handler.verify_and_parse(&headers, body);
        assert!(result.is_err());
    }

    #[test]
    fn test_linear_defaults_type_to_unknown() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"data": {"id": 1}}"#;
        let signature = handler.verifier.compute(body);
        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "unknown");
    }

    #[test]
    fn test_slack_preserves_headers() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback"}"#;

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
        headers.insert("content-type".to_string(), "application/json".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.headers.len(), 3);
    }

    #[test]
    fn test_slack_defaults_event_type_unknown() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"data":"no type field here"}"#;

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
        assert_eq!(event.event_type, "unknown");
    }

    #[test]
    fn test_slack_missing_event_id_uses_deterministic_fallback_id() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback"}"#; // No event_id field

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

        let first = handler.verify_and_parse(&headers, body).unwrap();
        let second = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(
            first.id,
            deterministic_event_id_with_context(
                "slack",
                "unknown",
                body,
                Some(&timestamp.to_string())
            )
        );
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn test_slack_missing_event_id_does_not_alias_same_payload_across_timestamps() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"url_verification","challenge":"abc"}"#;
        let verifier = HmacSha256Verifier::new(signing_secret);

        let first_timestamp = Utc::now().timestamp();
        let second_timestamp = first_timestamp + 1;

        let first_signature = verifier
            .compute(format!("v0:{first_timestamp}:{}", String::from_utf8_lossy(body)).as_bytes());
        let second_signature = verifier
            .compute(format!("v0:{second_timestamp}:{}", String::from_utf8_lossy(body)).as_bytes());

        let mut first_headers = HashMap::new();
        first_headers.insert(
            "x-slack-signature".to_string(),
            format!("v0={first_signature}"),
        );
        first_headers.insert(
            "x-slack-request-timestamp".to_string(),
            first_timestamp.to_string(),
        );

        let mut second_headers = HashMap::new();
        second_headers.insert(
            "x-slack-signature".to_string(),
            format!("v0={second_signature}"),
        );
        second_headers.insert(
            "x-slack-request-timestamp".to_string(),
            second_timestamp.to_string(),
        );

        let first_event = handler.verify_and_parse(&first_headers, body).unwrap();
        let second_event = handler.verify_and_parse(&second_headers, body).unwrap();

        assert_ne!(first_event.id, second_event.id);
    }

    #[test]
    fn test_slack_verifies_against_literal_timestamp_header_value() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"url_verification","challenge":"abc"}"#;
        let timestamp_str = format!("0{}", Utc::now().timestamp());
        let verifier = HmacSha256Verifier::new(signing_secret);
        let computed = verifier
            .compute(format!("v0:{timestamp_str}:{}", String::from_utf8_lossy(body)).as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), format!("v0={computed}"));
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            timestamp_str.clone(),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(
            event.id,
            deterministic_event_id_with_context(
                "slack",
                "url_verification",
                body,
                Some(timestamp_str.as_str())
            )
        );
    }

    #[test]
    fn test_slack_invalid_json_body() {
        let signing_secret = "test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = b"not-json";

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

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::JsonError(_))));
    }

    #[test]
    fn test_slack_wrong_signature_fails() {
        let handler = SlackWebhook::new("correct_secret");
        let body = br#"{"type":"event_callback"}"#;

        let timestamp = Utc::now().timestamp();
        let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let wrong_verifier = HmacSha256Verifier::new("wrong_secret");
        let computed = wrong_verifier.compute(base_string.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".to_string(), format!("v0={computed}"));
        headers.insert(
            "x-slack-request-timestamp".to_string(),
            timestamp.to_string(),
        );

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::InvalidSignature)));
    }

    #[test]
    fn test_webhook_provider_all_display_values_unique() {
        let displays: Vec<String> = [
            WebhookProvider::GitHub,
            WebhookProvider::Stripe,
            WebhookProvider::Slack,
            WebhookProvider::Linear,
            WebhookProvider::Discord,
            WebhookProvider::Custom,
        ]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

        for (i, a) in displays.iter().enumerate() {
            for (j, b) in displays.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_stripe_preserves_headers() {
        let handler = StripeWebhook::new("secret");
        let body = br#"{"id":"evt_1","type":"test"}"#;
        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(signed_payload.as_bytes());

        let mut headers = HashMap::new();
        headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp},v1={sig}"),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.headers.len(), 2);
    }

    #[test]
    fn test_linear_preserves_headers() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type":"Issue","webhookId":"wh_1"}"#;
        let signature = handler.verifier.compute(body);

        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-custom".to_string(), "value".to_string());

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.headers.len(), 3);
    }

    #[test]
    fn test_github_webhook_wrong_secret() {
        let handler = GitHubWebhook::new("correct");
        let body = br#"{"action":"test"}"#;
        let wrong_verifier = HmacSha256Verifier::new("wrong");
        let signature = format!("sha256={}", wrong_verifier.compute(body));

        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());

        let result = handler.verify_and_parse(&headers, body);
        assert!(matches!(result, Err(WebhookError::InvalidSignature)));
    }

    #[test]
    fn test_stripe_parse_negative_timestamp() {
        let result = StripeWebhook::parse_stripe_signature("t=-1,v1=abc");
        assert!(result.is_ok());
        let (_, ts, _) = result.unwrap();
        assert_eq!(ts, -1);
    }

    #[test]
    fn test_stripe_parse_zero_timestamp() {
        let (raw_ts, ts, sigs) = StripeWebhook::parse_stripe_signature("t=0,v1=sig").unwrap();
        assert_eq!(raw_ts, "0");
        assert_eq!(ts, 0);
        assert_eq!(sigs, vec!["sig"]);
    }

    #[test]
    fn test_stripe_multiple_v1_one_correct() {
        let handler = StripeWebhook::new("secret");
        let body = br#"{"id":"evt_1","type":"test"}"#;
        let timestamp = Utc::now().timestamp();
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let verifier = HmacSha256Verifier::new("secret");
        let correct_sig = verifier.compute(signed_payload.as_bytes());
        let sig_header = format!("t={timestamp},v1=wrong_sig,v1={correct_sig}");

        let mut headers = HashMap::new();
        headers.insert("stripe-signature".to_string(), sig_header);

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.id, "evt_1");
    }

    // ── Batch 5: SunnyMoose test expansion ──

    #[test]
    fn test_github_webhook_sets_provider_github() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action":"test"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());
        headers.insert("x-github-delivery".to_string(), "d1".to_string());
        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.provider, "github");
    }

    #[test]
    fn test_stripe_webhook_sets_provider_stripe() {
        let handler = StripeWebhook::new("secret");
        let body = br#"{"id":"evt_1","type":"charge.created"}"#;
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
        assert_eq!(event.provider, "stripe");
    }

    #[test]
    fn test_linear_webhook_sets_provider_linear() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type":"Issue","webhookId":"wh_1"}"#;
        let signature = handler.verifier.compute(body);
        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);
        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.provider, "linear");
    }

    #[test]
    fn test_slack_webhook_sets_provider_slack() {
        let signing_secret = "test-secret-for-provider";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback"}"#;
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
        assert_eq!(event.provider, "slack");
    }

    #[test]
    fn test_stripe_parse_signature_large_timestamp() {
        let (raw_ts, ts, sigs) =
            StripeWebhook::parse_stripe_signature("t=9999999999999,v1=sig").unwrap();
        assert_eq!(raw_ts, "9999999999999");
        assert_eq!(ts, 9_999_999_999_999);
        assert_eq!(sigs, vec!["sig"]);
    }

    #[test]
    fn test_stripe_verifies_against_literal_timestamp_header_value() {
        let secret = "secret";
        let handler = StripeWebhook::new(secret);
        let body = br#"{"type":"charge.created"}"#;
        let timestamp_str = format!("0{}", Utc::now().timestamp());
        let verifier = HmacSha256Verifier::new(secret);
        let sig = verifier
            .compute(format!("{timestamp_str}.{}", String::from_utf8_lossy(body)).as_bytes());

        let mut headers = HashMap::new();
        headers.insert(
            "stripe-signature".to_string(),
            format!("t={timestamp_str},v1={sig}"),
        );

        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(
            event.id,
            deterministic_event_id_with_context(
                "stripe",
                "charge.created",
                body,
                Some(timestamp_str.as_str())
            )
        );
    }

    #[test]
    fn test_stripe_parse_signature_whitespace_in_parts() {
        // Stripe signatures shouldn't have whitespace but test robustness
        let result = StripeWebhook::parse_stripe_signature("t= 123,v1=abc");
        // "t= 123" won't parse as i64
        assert!(result.is_err());
    }

    #[test]
    fn test_github_webhook_with_nested_payload() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action":"opened","pull_request":{"number":42,"head":{"ref":"feature","sha":"abc123"}}}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "pull_request".to_string());
        headers.insert("x-github-delivery".to_string(), "d_nested".to_string());
        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.get_str("action"), Some("opened"));
        assert_eq!(event.get_i64("pull_request.number"), Some(42));
        assert_eq!(event.get_str("pull_request.head.ref"), Some("feature"));
    }

    #[test]
    fn test_stripe_validate_timestamp_negative() {
        let handler =
            StripeWebhook::new("secret").with_timestamp_tolerance(Duration::from_secs(300));
        // Negative timestamp is far in the past
        assert!(matches!(
            handler.validate_timestamp(-1),
            Err(WebhookError::TimestampValidation { .. })
        ));
    }

    #[test]
    fn test_github_webhook_taint_flags_are_set() {
        let handler = GitHubWebhook::new("secret");
        let body = br#"{"action":"test"}"#;
        let signature = format!("sha256={}", handler.verifier.compute(body));
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "push".to_string());
        headers.insert("x-github-delivery".to_string(), "d_taint".to_string());
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
    fn test_stripe_taint_flags_are_set() {
        let handler = StripeWebhook::new("secret");
        let body = br#"{"id":"evt_t","type":"charge.created"}"#;
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
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_slack_taint_flags_are_set() {
        let signing_secret = "taint-test-secret";
        let handler = SlackWebhook::new(signing_secret);
        let body = br#"{"type":"event_callback","event_id":"Ev_taint"}"#;
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
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_webhook_provider_debug_contains_variant_name() {
        assert!(format!("{:?}", WebhookProvider::GitHub).contains("GitHub"));
        assert!(format!("{:?}", WebhookProvider::Stripe).contains("Stripe"));
        assert!(format!("{:?}", WebhookProvider::Slack).contains("Slack"));
        assert!(format!("{:?}", WebhookProvider::Linear).contains("Linear"));
        assert!(format!("{:?}", WebhookProvider::Discord).contains("Discord"));
        assert!(format!("{:?}", WebhookProvider::Custom).contains("Custom"));
    }

    #[test]
    fn test_stripe_parse_signature_v1_empty_value() {
        let result = StripeWebhook::parse_stripe_signature("t=123,v1=");
        match result {
            Err(WebhookError::InvalidPayload(msg)) => {
                assert!(
                    msg.contains("v1"),
                    "error should name the malformed component: {msg}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    #[test]
    fn test_linear_webhook_unicode_payload() {
        let handler = LinearWebhook::new("secret");
        let body = br#"{"type":"Comment","webhookId":"wh_\u00e9","data":"unicode \u00f1"}"#;
        let signature = handler.verifier.compute(body);
        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), signature);
        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert_eq!(event.event_type, "Comment");
    }

    #[test]
    fn test_github_null_payload_value() {
        let handler = GitHubWebhook::new("secret");
        let body = b"null";
        let signature = format!("sha256={}", handler.verifier.compute(body));
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".to_string(), signature);
        headers.insert("x-github-event".to_string(), "ping".to_string());
        headers.insert("x-github-delivery".to_string(), "d_null".to_string());
        let event = handler.verify_and_parse(&headers, body).unwrap();
        assert!(event.payload.is_null());
    }

    #[test]
    fn test_stripe_parse_signature_multiple_timestamps_rejected() {
        let result = StripeWebhook::parse_stripe_signature("t=100,t=200,v1=sig");
        match result {
            Err(WebhookError::InvalidPayload(msg)) => {
                assert!(
                    msg.contains("multiple timestamp"),
                    "error should explain the ambiguity: {msg}"
                );
            }
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    #[test]
    fn test_slack_wrong_secret_different_from_missing() {
        let handler = SlackWebhook::new("correct");
        let body = br#"{"type":"test"}"#;
        let timestamp = Utc::now().timestamp();

        // Missing signature header
        let headers_no_sig = HashMap::new();
        let result_no_sig = handler.verify_and_parse(&headers_no_sig, body);
        assert!(matches!(
            result_no_sig,
            Err(WebhookError::MissingSignature(_))
        ));

        // Wrong signature
        let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
        let wrong = HmacSha256Verifier::new("wrong");
        let computed = wrong.compute(base_string.as_bytes());
        let mut headers_wrong = HashMap::new();
        headers_wrong.insert("x-slack-signature".to_string(), format!("v0={computed}"));
        headers_wrong.insert(
            "x-slack-request-timestamp".to_string(),
            timestamp.to_string(),
        );
        let result_wrong = handler.verify_and_parse(&headers_wrong, body);
        assert!(matches!(result_wrong, Err(WebhookError::InvalidSignature)));
    }

    #[test]
    fn test_linear_wrong_secret_different_from_missing() {
        let handler = LinearWebhook::new("correct");
        let body = br#"{"type":"Issue"}"#;

        // Missing signature
        let result_missing = handler.verify_and_parse(&HashMap::new(), body);
        assert!(matches!(
            result_missing,
            Err(WebhookError::MissingSignature(_))
        ));

        // Wrong signature
        let wrong = HmacSha256Verifier::new("wrong");
        let wrong_sig = wrong.compute(body);
        let mut headers = HashMap::new();
        headers.insert("linear-signature".to_string(), wrong_sig);
        let result_wrong = handler.verify_and_parse(&headers, body);
        assert!(result_wrong.is_err());
    }
}
