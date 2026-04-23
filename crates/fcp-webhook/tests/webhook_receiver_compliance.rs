use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use fcp_core::TaintFlag;
use fcp_webhook::{
    GitHubWebhook, HmacSha256Verifier, SignatureVerifier, StripeWebhook, WebhookConfig,
    WebhookError, WebhookHandler,
};
use serde_json::{Value, json};

fn run_compliance_test<F>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
where
    F: FnOnce() -> Value + panic::UnwindSafe,
{
    let started = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    let duration_us = started.elapsed().as_micros();

    let (outcome, passed, failed, details) = result
        .as_ref()
        .map_or(("fail", 0_u32, assertions, Value::Null), |details| {
            ("pass", assertions, 0_u32, details.clone())
        });

    let log = json!({
        "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "level": "info",
        "test_name": test_name,
        "module": "fcp-webhook",
        "phase": phase,
        "operation": operation,
        "correlation_id": format!("fcp-webhook::{test_name}"),
        "result": outcome,
        "duration_us": duration_us,
        "assertions": {
            "passed": passed,
            "failed": failed,
        },
        "details": details,
    });
    println!("{log}");

    if let Err(payload) = result {
        panic::resume_unwind(payload);
    }
}

#[test]
fn signature_vector_hmac_sha256_is_stable_and_validates() {
    run_compliance_test(
        "signature_vector_hmac_sha256_is_stable_and_validates",
        "verify",
        "webhook.signature.verify",
        4,
        || {
            let verifier = HmacSha256Verifier::new("secret");
            let payload = b"test payload";
            let expected_signature =
                "f1f1fc517bb886ad22c56e51dae135aad082b2e3337bed35e2e44cd299324bd8";

            let computed_signature = verifier.compute(payload);
            assert_eq!(computed_signature, expected_signature);
            assert!(verifier.verify(payload, expected_signature).is_ok());
            let prefixed = format!("sha256={expected_signature}");
            assert!(verifier.verify(payload, &prefixed).is_ok());
            assert!(
                verifier
                    .verify(b"tampered payload", expected_signature)
                    .is_err()
            );

            json!({
                "vector_id": "hmac_sha256_secret_test_payload",
                "expected_signature": expected_signature,
            })
        },
    );
}

#[test]
fn github_provider_vector_known_good_and_tampered_payloads() {
    run_compliance_test(
        "github_provider_vector_known_good_and_tampered_payloads",
        "verify",
        "webhook.github.vector",
        5,
        || {
            let handler = GitHubWebhook::new("gh_secret_test");
            let payload = br#"{"action":"opened","issue":{"number":1}}"#;
            let expected_signature =
                "a2c0fd1a0bef03e34345f687745a1690684332161d72bcded76b00110befdd88";

            let mut headers = HashMap::new();
            headers.insert(
                "x-hub-signature-256".to_string(),
                format!("sha256={expected_signature}"),
            );
            headers.insert("x-github-event".to_string(), "issues".to_string());
            headers.insert("x-github-delivery".to_string(), "gh_evt_123".to_string());

            let event = handler
                .verify_and_parse(&headers, payload)
                .expect("known-good GitHub vector must verify");
            assert_eq!(event.id, "gh_evt_123");
            assert_eq!(event.event_type, "issues");

            let mut tampered = payload.to_vec();
            tampered[0] ^= 0x01;
            assert!(matches!(
                handler.verify_and_parse(&headers, &tampered),
                Err(WebhookError::InvalidSignature)
            ));

            let computed = HmacSha256Verifier::new("gh_secret_test").compute(payload);
            assert_eq!(computed, expected_signature);

            json!({
                "vector_id": "github_issue_opened_v1",
                "expected_signature": expected_signature,
                "event_id": event.id,
            })
        },
    );
}

#[test]
fn stripe_provider_vector_known_good_and_tampered_payloads() {
    run_compliance_test(
        "stripe_provider_vector_known_good_and_tampered_payloads",
        "verify",
        "webhook.stripe.vector",
        5,
        || {
            let handler =
                StripeWebhook::new("whsec_test").with_timestamp_tolerance(Duration::from_secs(5));
            let payload = br#"{"id":"evt_123","type":"payment_intent.succeeded"}"#;
            let timestamp = 1_700_000_000_i64;
            let expected_signature =
                "6f372f5ee7b8512142fa568d371d8674b3accc526c220605b289be8a123d557c";

            let mut headers = HashMap::new();
            headers.insert(
                "stripe-signature".to_string(),
                format!("t={timestamp},v1={expected_signature}"),
            );

            let event = handler
                .verify_and_parse(&headers, payload)
                .expect("known-good Stripe vector must verify");
            assert_eq!(event.id, "evt_123");
            assert_eq!(event.event_type, "payment_intent.succeeded");

            let mut tampered = payload.to_vec();
            tampered[0] ^= 0x01;
            assert!(matches!(
                handler.verify_and_parse(&headers, &tampered),
                Err(WebhookError::InvalidSignature)
            ));

            let signed = format!("{timestamp}.{}", String::from_utf8_lossy(payload));
            let computed = HmacSha256Verifier::new("whsec_test").compute(signed.as_bytes());
            assert_eq!(computed, expected_signature);

            json!({
                "vector_id": "stripe_payment_intent_succeeded_v1",
                "timestamp": timestamp,
                "expected_signature": expected_signature,
                "event_id": event.id,
            })
        },
    );
}

#[test]
fn replay_window_expires_entries_after_ttl() {
    run_compliance_test(
        "replay_window_expires_entries_after_ttl",
        "verify",
        "webhook.replay.window",
        2,
        || {
            let verifier = HmacSha256Verifier::new("secret");
            let config = WebhookConfig::new().with_idempotency_ttl(Duration::from_millis(1));
            let handler = WebhookHandler::with_config(verifier, "github", config);

            handler.record_event("evt_ttl").unwrap();
            assert!(matches!(
                handler.check_replay("evt_ttl"),
                Err(WebhookError::ReplayDetected { .. })
            ));

            thread::sleep(Duration::from_millis(5));
            assert!(handler.check_replay("evt_ttl").is_ok());

            json!({
                "event_id": "evt_ttl",
                "ttl_ms": 1,
            })
        },
    );
}

#[test]
fn payload_size_limits_enforce_boundary_conditions() {
    run_compliance_test(
        "payload_size_limits_enforce_boundary_conditions",
        "verify",
        "webhook.payload.bounds",
        3,
        || {
            let verifier = HmacSha256Verifier::new("secret");
            let config = WebhookConfig::new().with_max_payload_size(8);
            let handler = WebhookHandler::with_config(verifier.clone(), "github", config);

            let allowed_payload = b"12345678";
            let allowed_signature = verifier.compute(allowed_payload);
            assert!(handler.verify(allowed_payload, &allowed_signature).is_ok());

            let oversized_payload = b"123456789";
            let oversized_signature = verifier.compute(oversized_payload);
            let error = handler
                .verify(oversized_payload, &oversized_signature)
                .expect_err("payload one byte above limit must be rejected");
            assert!(matches!(
                error,
                WebhookError::PayloadTooLarge { size: 9, limit: 8 }
            ));

            json!({
                "allowed_size": 8,
                "rejected_size": 9,
            })
        },
    );
}

#[test]
fn parsed_webhook_events_include_default_taint_labels() {
    run_compliance_test(
        "parsed_webhook_events_include_default_taint_labels",
        "verify",
        "webhook.taint.labeling",
        4,
        || {
            let handler = GitHubWebhook::new("secret");
            let payload = br#"{"action":"opened","issue":{"number":1}}"#;
            let signature = HmacSha256Verifier::new("secret").compute(payload);

            let mut headers = HashMap::new();
            headers.insert(
                "x-hub-signature-256".to_string(),
                format!("sha256={signature}"),
            );
            headers.insert("x-github-event".to_string(), "issues".to_string());
            headers.insert("x-github-delivery".to_string(), "evt_taint_1".to_string());

            let event = handler
                .verify_and_parse(&headers, payload)
                .expect("valid GitHub webhook should parse");
            assert!(
                event
                    .metadata
                    .taint_flags
                    .contains(TaintFlag::WebhookInjected)
            );
            assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));

            let encoded = serde_json::to_value(&event).expect("event should serialize");
            let taint_flags = encoded["metadata"]["taint_flags"]
                .as_array()
                .expect("metadata.taint_flags should serialize as an array");
            assert!(taint_flags.iter().any(|flag| flag == "WEBHOOK_INJECTED"));
            assert!(taint_flags.iter().any(|flag| flag == "PUBLIC_INPUT"));

            json!({
                "event_id": event.id,
                "taint_flags": taint_flags,
            })
        },
    );
}
