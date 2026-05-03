//! Stripe-style timestamped HMAC verifier properties.
//!
//! The libFuzzer target covers arbitrary headers and bodies. This harness pins
//! replay-window, future-timestamp, truncation, and padding behavior with
//! deterministic positive and negative examples.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use fcp_webhook::{HmacSha256Verifier, StripeWebhook, WebhookError};
use proptest::prelude::*;
use serde_json::json;

const STRIPE_SECRET: &[u8] = b"whsec_property_test_secret_2026";

fn stripe_body(id_suffix: &[u8], event_kind: u8, payload: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": format!("evt_{}", hex::encode(id_suffix)),
        "type": format!("property.event_{event_kind}"),
        "data": {
            "object": {
                "payload_hex": hex::encode(payload),
            },
        },
    }))
    .expect("Stripe event fixture serializes")
}

fn stripe_signed_payload(timestamp: i64, body: &[u8]) -> Vec<u8> {
    let mut payload = timestamp.to_string().into_bytes();
    payload.push(b'.');
    payload.extend_from_slice(body);
    payload
}

fn stripe_signature(timestamp: i64, body: &[u8]) -> String {
    HmacSha256Verifier::new(STRIPE_SECRET).compute(&stripe_signed_payload(timestamp, body))
}

fn stripe_header(timestamp: i64, signature: &str) -> String {
    format!("t={timestamp},v1={signature}")
}

fn stripe_headers(signature_header: String) -> HashMap<String, String> {
    HashMap::from([("stripe-signature".to_string(), signature_header)])
}

fn stripe_verifier() -> StripeWebhook {
    StripeWebhook::new(STRIPE_SECRET).with_timestamp_tolerance(Duration::from_secs(30))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        ..ProptestConfig::default()
    })]

    #[test]
    fn stripe_timestamped_hmac_accepts_current_signatures(
        id_suffix in proptest::collection::vec(any::<u8>(), 0usize..=16),
        event_kind in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0usize..=256),
    ) {
        let body = stripe_body(&id_suffix, event_kind, &payload);
        let now = Utc::now().timestamp();
        let signature = stripe_signature(now, &body);
        let headers = stripe_headers(stripe_header(now, &signature));

        let parsed = stripe_verifier().verify_and_parse(&headers, &body);
        prop_assert!(parsed.is_ok(), "fresh Stripe signature was rejected: {parsed:?}");
    }

    #[test]
    fn stripe_replay_and_future_timestamps_fail_closed(
        id_suffix in proptest::collection::vec(any::<u8>(), 0usize..=16),
        event_kind in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0usize..=256),
        offset in prop_oneof![(-86400i64..=-120), (120i64..=86400)],
    ) {
        let body = stripe_body(&id_suffix, event_kind, &payload);
        let timestamp = Utc::now().timestamp() + offset;
        let signature = stripe_signature(timestamp, &body);
        let headers = stripe_headers(stripe_header(timestamp, &signature));

        let parsed = stripe_verifier().verify_and_parse(&headers, &body);
        prop_assert!(
            matches!(parsed, Err(WebhookError::TimestampValidation { .. })),
            "skewed Stripe timestamp escaped timestamp validation: {parsed:?}"
        );
    }

    #[test]
    fn stripe_truncated_and_padded_hmac_values_fail_closed(
        id_suffix in proptest::collection::vec(any::<u8>(), 0usize..=16),
        event_kind in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0usize..=256),
        truncate_at in 0usize..64,
        prefix_padding in any::<bool>(),
    ) {
        let body = stripe_body(&id_suffix, event_kind, &payload);
        let now = Utc::now().timestamp();
        let signature = stripe_signature(now, &body);
        let tampered_signature = if prefix_padding {
            format!("00{signature}")
        } else {
            signature[..truncate_at].to_string()
        };
        let headers = stripe_headers(stripe_header(now, &tampered_signature));

        let parsed = stripe_verifier().verify_and_parse(&headers, &body);
        prop_assert!(
            matches!(
                parsed,
                Err(WebhookError::InvalidSignature | WebhookError::InvalidPayload(_))
            ),
            "tampered Stripe signature escaped verification: {parsed:?}"
        );
    }
}
