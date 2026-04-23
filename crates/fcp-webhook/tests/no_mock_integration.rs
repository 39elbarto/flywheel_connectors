//! No-mock integration tests for fcp-webhook.
//!
//! These tests exercise the full webhook pipeline (signature verification,
//! event parsing, routing, dead letter queue) without any external mocks.

// Pre-existing tests cover the deprecated check_replay + record_event pair
// (br-v3wrz). Claim_event is the atomic replacement; see
// claim_event_rejects_duplicate_under_split_call_pattern for the canonical
// regression. Keep the legacy tests running under allow(deprecated).
#![allow(deprecated)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use fcp_core::TaintFlag;
use fcp_webhook::{
    DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_TIMESTAMP_TOLERANCE, DeadLetterQueue, DeliveryStatus,
    Ed25519Verifier, EventRouter, EventSubscription, GitHubWebhook, HmacSha1Verifier,
    HmacSha256Verifier, LinearWebhook, SignatureAlgorithm, SignatureVerifier, SlackWebhook,
    StripeWebhook, WebhookConfig, WebhookError, WebhookEvent, WebhookHandler, WebhookProvider,
};

// ─── Full pipeline tests ──────────────────────────────────────────────

#[test]
fn pipeline_github_verify_route_deliver() {
    // 1. Create GitHub handler + router + DLQ
    let github = GitHubWebhook::new("gh_webhook_secret_2026");
    let handler = WebhookHandler::new(HmacSha256Verifier::new("gh_webhook_secret_2026"), "github");
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["push".into()]),
        "ci_trigger",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["issues".into(), "issue_comment".into()]),
        "issue_tracker",
    );
    router.subscribe(
        EventSubscription::all().with_provider("github"),
        "audit_log",
    );
    let dlq = DeadLetterQueue::new(100);

    // 2. Simulate incoming webhook
    let body = br#"{"action":"opened","issue":{"number":42,"title":"Test issue"}}"#;
    let verifier = HmacSha256Verifier::new("gh_webhook_secret_2026");
    let signature = format!("sha256={}", verifier.compute(body));

    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".into(), signature);
    headers.insert("x-github-event".into(), "issues".into());
    headers.insert("x-github-delivery".into(), "del_42".into());

    // 3. Parse and verify
    let event = github.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "del_42");
    assert_eq!(event.event_type, "issues");
    assert_eq!(event.provider, "github");

    // 4. Check idempotency
    assert!(handler.claim_event(&event.id).is_ok());
    assert!(matches!(
        handler.claim_event(&event.id),
        Err(WebhookError::ReplayDetected { .. })
    ));

    // 5. Route event
    let handlers = router.route(&event);
    assert_eq!(handlers.len(), 2);
    assert!(handlers.contains(&"issue_tracker"));
    assert!(handlers.contains(&"audit_log"));
    assert!(!handlers.contains(&"ci_trigger"));

    // 6. DLQ should be empty
    assert!(dlq.is_empty());
}

#[test]
fn pipeline_github_push_routes_to_ci() {
    let github = GitHubWebhook::new("secret");
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["push".into()]),
        "ci_trigger",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["issues".into()]),
        "issue_handler",
    );

    let body = br#"{"ref":"refs/heads/main","commits":[]}"#;
    let sig = format!("sha256={}", HmacSha256Verifier::new("secret").compute(body));
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".into(), sig);
    headers.insert("x-github-event".into(), "push".into());
    headers.insert("x-github-delivery".into(), "del_push_1".into());

    let event = github.verify_and_parse(&headers, body).unwrap();
    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["ci_trigger"]);
}

#[test]
fn pipeline_github_missing_delivery_keeps_distinct_event_headers_distinct() {
    let github = GitHubWebhook::new("secret");
    let handler = WebhookHandler::new(HmacSha256Verifier::new("secret"), "github");
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["star".into()]),
        "star_handler",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["watch".into()]),
        "watch_handler",
    );

    let body = br#"{"action":"created"}"#;
    let sig = format!("sha256={}", HmacSha256Verifier::new("secret").compute(body));

    let mut star_headers = HashMap::new();
    star_headers.insert("x-hub-signature-256".into(), sig.clone());
    star_headers.insert("x-github-event".into(), "star".into());

    let mut watch_headers = HashMap::new();
    watch_headers.insert("x-hub-signature-256".into(), sig);
    watch_headers.insert("x-github-event".into(), "watch".into());

    let star_event = github.verify_and_parse(&star_headers, body).unwrap();
    let watch_event = github.verify_and_parse(&watch_headers, body).unwrap();

    assert_eq!(star_event.event_type, "star");
    assert_eq!(watch_event.event_type, "watch");
    assert_ne!(star_event.id, watch_event.id);
    assert_eq!(router.route(&star_event), vec!["star_handler"]);
    assert_eq!(router.route(&watch_event), vec!["watch_handler"]);
    assert!(handler.claim_event(&star_event.id).is_ok());
    assert!(handler.claim_event(&watch_event.id).is_ok());
}

#[test]
fn pipeline_stripe_verify_route_with_timestamp() {
    let secret = "whsec_stripe_secret_key";
    let stripe = StripeWebhook::new(secret);
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["payment_intent.*".into()]),
        "payment_handler",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["charge.*".into()]),
        "charge_handler",
    );

    let body = br#"{"id":"evt_stripe_1","type":"payment_intent.succeeded","data":{"amount":2000}}"#;
    let timestamp = Utc::now().timestamp();
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let sig = HmacSha256Verifier::new(secret).compute(signed_payload.as_bytes());
    let sig_header = format!("t={timestamp},v1={sig}");

    let mut headers = HashMap::new();
    headers.insert("stripe-signature".into(), sig_header);

    let event = stripe.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "evt_stripe_1");
    assert_eq!(event.event_type, "payment_intent.succeeded");
    assert_eq!(event.provider, "stripe");

    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["payment_handler"]);
}

#[test]
fn pipeline_slack_verify_route_event_callback() {
    let signing_secret = "slack_signing_secret_2026";
    let slack = SlackWebhook::new(signing_secret);
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["message".into()]),
        "message_handler",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["url_verification".into()]),
        "challenge_handler",
    );

    let body = br#"{"type":"event_callback","event":{"type":"message","text":"hello"},"event_id":"Ev_slack_1"}"#;
    let timestamp = Utc::now().timestamp();
    let base_string = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
    let verifier = HmacSha256Verifier::new(signing_secret);
    let computed = verifier.compute(base_string.as_bytes());

    let mut headers = HashMap::new();
    headers.insert("x-slack-signature".into(), format!("v0={computed}"));
    headers.insert("x-slack-request-timestamp".into(), timestamp.to_string());

    let event = slack.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "Ev_slack_1");
    assert_eq!(event.event_type, "message");
    assert_eq!(event.provider, "slack");

    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["message_handler"]);
}

#[test]
fn pipeline_slack_missing_event_id_keeps_distinct_timestamps_separate() {
    let signing_secret = "slack_signing_secret_2026";
    let slack = SlackWebhook::new(signing_secret);
    let handler = WebhookHandler::new(
        HmacSha256Verifier::new(signing_secret),
        WebhookProvider::Slack.to_string(),
    );
    let body = br#"{"type":"url_verification","challenge":"abc"}"#;

    let first_timestamp = Utc::now().timestamp();
    let first_base = format!("v0:{first_timestamp}:{}", String::from_utf8_lossy(body));
    let verifier = HmacSha256Verifier::new(signing_secret);
    let first_signature = verifier.compute(first_base.as_bytes());

    let mut first_headers = HashMap::new();
    first_headers.insert("x-slack-signature".into(), format!("v0={first_signature}"));
    first_headers.insert(
        "x-slack-request-timestamp".into(),
        first_timestamp.to_string(),
    );

    let second_timestamp = first_timestamp + 1;
    let second_base = format!("v0:{second_timestamp}:{}", String::from_utf8_lossy(body));
    let second_signature = verifier.compute(second_base.as_bytes());

    let mut second_headers = HashMap::new();
    second_headers.insert("x-slack-signature".into(), format!("v0={second_signature}"));
    second_headers.insert(
        "x-slack-request-timestamp".into(),
        second_timestamp.to_string(),
    );

    let first_event = slack.verify_and_parse(&first_headers, body).unwrap();
    let second_event = slack.verify_and_parse(&second_headers, body).unwrap();

    assert_ne!(first_event.id, second_event.id);
    assert!(handler.claim_event(&first_event.id).is_ok());
    assert!(handler.claim_event(&second_event.id).is_ok());
}

#[test]
fn pipeline_linear_verify_and_route() {
    let linear = LinearWebhook::new("linear_secret");
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["Issue".into()]),
        "issue_sync",
    );

    let body =
        br#"{"type":"Issue","action":"create","webhookId":"wh_lin_1","data":{"title":"Bug fix"}}"#;
    let sig = HmacSha256Verifier::new("linear_secret").compute(body);
    let mut headers = HashMap::new();
    headers.insert("linear-signature".into(), sig);

    let event = linear.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "wh_lin_1");
    assert_eq!(event.event_type, "Issue");

    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["issue_sync"]);
}

// ─── Multi-provider concurrent processing ─────────────────────────────

#[test]
fn concurrent_multi_provider_idempotency() {
    let webhook_handler = Arc::new(WebhookHandler::new(
        HmacSha256Verifier::new("secret"),
        "multi",
    ));

    let mut join_handles = vec![];
    for i in 0..20 {
        let wh = Arc::clone(&webhook_handler);
        join_handles.push(thread::spawn(move || {
            let event_id = format!("provider_{}_evt_{}", i % 4, i / 4);
            wh.claim_event(&event_id)
        }));
    }

    let mut successes = 0;
    let mut replays = 0;
    for jh in join_handles {
        match jh.join().unwrap() {
            Ok(()) => successes += 1,
            Err(WebhookError::ReplayDetected { .. }) => replays += 1,
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }

    // 20 events, 5 unique per provider, 4 providers = 20 unique event IDs
    assert_eq!(successes, 20);
    assert_eq!(replays, 0);
}

#[test]
fn concurrent_same_event_only_one_wins() {
    let webhook_handler = Arc::new(WebhookHandler::new(
        HmacSha256Verifier::new("secret"),
        "race",
    ));

    let mut join_handles = vec![];
    for _ in 0..10 {
        let wh = Arc::clone(&webhook_handler);
        join_handles.push(thread::spawn(move || wh.claim_event("singleton_event")));
    }

    let mut wins = 0;
    let mut losses = 0;
    for jh in join_handles {
        match jh.join().unwrap() {
            Ok(()) => wins += 1,
            Err(WebhookError::ReplayDetected { .. }) => losses += 1,
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }

    assert_eq!(wins, 1, "Exactly one thread should win");
    assert_eq!(losses, 9, "Nine threads should detect replay");
}

// ─── Dead letter queue pipeline ───────────────────────────────────────

#[test]
fn dlq_overflow_evicts_oldest_events() {
    let dlq = DeadLetterQueue::new(5);

    for i in 0..10 {
        dlq.push(WebhookEvent::new(format!("evt_{i}"), "test", "provider"));
    }

    assert_eq!(dlq.len(), 5);
    let all = dlq.all();
    // Only events 5-9 should remain
    for (idx, event) in all.iter().enumerate() {
        assert_eq!(event.id, format!("evt_{}", idx + 5));
        assert_eq!(event.metadata.status, DeliveryStatus::DeadLettered);
    }
}

#[test]
fn dlq_reprocessing_after_clear() {
    let dlq = DeadLetterQueue::new(10);
    let handler = WebhookHandler::new(HmacSha256Verifier::new("s"), "test");

    // Simulate 3 failed deliveries
    for i in 0..3 {
        let event = WebhookEvent::new(format!("failed_{i}"), "test", "p");
        handler.claim_event(&event.id).unwrap();
        dlq.push(event);
    }

    assert_eq!(dlq.len(), 3);

    // "Reprocess" by removing one
    let reprocessed = dlq.remove("failed_1").unwrap();
    assert_eq!(reprocessed.id, "failed_1");
    assert_eq!(dlq.len(), 2);

    // Clear remaining
    dlq.clear();
    assert!(dlq.is_empty());
}

// ─── Event routing edge cases ─────────────────────────────────────────

#[test]
fn router_overlapping_wildcard_subscriptions() {
    let mut router = EventRouter::new();
    router.subscribe(EventSubscription::all(), "catch_all");
    router.subscribe(
        EventSubscription::for_types(vec!["issue.*".into()]),
        "issue_wildcard",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["issue.opened".into()]),
        "issue_opened_exact",
    );
    router.subscribe(
        EventSubscription::all().with_provider("github"),
        "github_all",
    );

    let event = WebhookEvent::new("e1", "issue.opened", "github");
    let handlers = router.route(&event);
    assert_eq!(handlers.len(), 4);
    assert!(handlers.contains(&"catch_all"));
    assert!(handlers.contains(&"issue_wildcard"));
    assert!(handlers.contains(&"issue_opened_exact"));
    assert!(handlers.contains(&"github_all"));

    // Non-GitHub issue → no github_all
    let event2 = WebhookEvent::new("e2", "issue.opened", "gitlab");
    let handlers2 = router.route(&event2);
    assert_eq!(handlers2.len(), 3);
    assert!(!handlers2.contains(&"github_all"));

    // Push event → only catch_all and github_all
    let event3 = WebhookEvent::new("e3", "push", "github");
    let handlers3 = router.route(&event3);
    assert_eq!(handlers3.len(), 2);
    assert!(handlers3.contains(&"catch_all"));
    assert!(handlers3.contains(&"github_all"));
}

#[test]
fn router_no_match_returns_empty() {
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["push".into()]).with_provider("github"),
        "gh_push",
    );

    let event = WebhookEvent::new("e1", "issues", "github");
    assert!(router.route(&event).is_empty());

    let event2 = WebhookEvent::new("e2", "push", "gitlab");
    assert!(router.route(&event2).is_empty());
}

// ─── Signature cross-verification ─────────────────────────────────────

#[test]
fn hmac_sha256_different_secrets_reject_cross_verify() {
    let v1 = HmacSha256Verifier::new("secret_alpha");
    let v2 = HmacSha256Verifier::new("secret_beta");

    let payload = b"webhook payload data";
    let sig1 = v1.compute(payload);
    let sig2 = v2.compute(payload);

    assert_ne!(sig1, sig2);
    assert!(v1.verify(payload, &sig1).is_ok());
    assert!(v1.verify(payload, &sig2).is_err());
    assert!(v2.verify(payload, &sig2).is_ok());
    assert!(v2.verify(payload, &sig1).is_err());
}

#[test]
fn hmac_sha1_different_secrets_reject_cross_verify() {
    let v1 = HmacSha1Verifier::new("secret_one");
    let v2 = HmacSha1Verifier::new("secret_two");

    let payload = b"webhook data";
    let sig1 = v1.compute(payload);

    assert!(v1.verify(payload, &sig1).is_ok());
    assert!(v2.verify(payload, &sig1).is_err());
}

#[test]
fn ed25519_verify_with_keypair() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let verifier = Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();

    let payloads = [
        b"hello world".as_slice(),
        b"",
        &[0u8; 1024],
        b"unicode: \xc3\xa9\xc3\xa0\xc3\xbc",
    ];

    for payload in &payloads {
        let signature = signing_key.sign(payload);
        let sig_hex = hex::encode(signature.to_bytes());
        assert!(verifier.verify(payload, &sig_hex).is_ok());
    }

    // Wrong payload fails
    let sig = signing_key.sign(b"original");
    let sig_hex = hex::encode(sig.to_bytes());
    assert!(verifier.verify(b"tampered", &sig_hex).is_err());
}

// ─── Algorithm identification ─────────────────────────────────────────

#[test]
fn each_verifier_reports_correct_algorithm() {
    let sha256 = HmacSha256Verifier::new("s");
    assert_eq!(sha256.algorithm(), SignatureAlgorithm::HmacSha256);

    let sha1 = HmacSha1Verifier::new("s");
    assert_eq!(sha1.algorithm(), SignatureAlgorithm::HmacSha1);

    let ed_key = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let signing = ed25519_dalek::SigningKey::from_bytes(&ed_key);
    let ed = Ed25519Verifier::from_bytes(&signing.verifying_key().to_bytes()).unwrap();
    assert_eq!(ed.algorithm(), SignatureAlgorithm::Ed25519);
}

// ─── Taint flag propagation ───────────────────────────────────────────

#[test]
fn all_providers_set_taint_flags() {
    // GitHub
    let gh = GitHubWebhook::new("s");
    let body = b"{}";
    let sig = format!("sha256={}", HmacSha256Verifier::new("s").compute(body));
    let mut h = HashMap::new();
    h.insert("x-hub-signature-256".into(), sig);
    h.insert("x-github-event".into(), "ping".into());
    let event = gh.verify_and_parse(&h, body).unwrap();
    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));

    // Linear
    let ln = LinearWebhook::new("s");
    let body = br#"{"type":"Issue"}"#;
    let sig = HmacSha256Verifier::new("s").compute(body);
    let mut h = HashMap::new();
    h.insert("linear-signature".into(), sig);
    let event = ln.verify_and_parse(&h, body).unwrap();
    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));

    // Stripe
    let st = StripeWebhook::new("s");
    let body = br#"{"id":"e","type":"t"}"#;
    let ts = Utc::now().timestamp();
    let signed = format!("{ts}.{}", String::from_utf8_lossy(body));
    let sig = HmacSha256Verifier::new("s").compute(signed.as_bytes());
    let mut h = HashMap::new();
    h.insert("stripe-signature".into(), format!("t={ts},v1={sig}"));
    let event = st.verify_and_parse(&h, body).unwrap();
    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));

    // Slack
    let sl = SlackWebhook::new("s");
    let body = br#"{"type":"event_callback"}"#;
    let ts = Utc::now().timestamp();
    let base = format!("v0:{ts}:{}", String::from_utf8_lossy(body));
    let computed = HmacSha256Verifier::new("s").compute(base.as_bytes());
    let mut h = HashMap::new();
    h.insert("x-slack-signature".into(), format!("v0={computed}"));
    h.insert("x-slack-request-timestamp".into(), ts.to_string());
    let event = sl.verify_and_parse(&h, body).unwrap();
    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
}

// ─── Replay protection with TTL expiry ────────────────────────────────

#[test]
fn replay_protection_ttl_lifecycle() {
    let config = WebhookConfig::new()
        .with_idempotency(true)
        .with_idempotency_ttl(Duration::from_millis(50));
    let handler = WebhookHandler::with_config(HmacSha256Verifier::new("s"), "test", config);

    // Claim event
    assert!(handler.claim_event("evt_ttl_1").is_ok());

    // Immediately replay should fail
    assert!(matches!(
        handler.claim_event("evt_ttl_1"),
        Err(WebhookError::ReplayDetected { .. })
    ));

    // Wait for TTL
    thread::sleep(Duration::from_millis(60));

    // After TTL, can re-claim
    assert!(handler.claim_event("evt_ttl_1").is_ok());
}

// ─── IP allowlist enforcement ─────────────────────────────────────────

#[test]
fn ip_allowlist_enforcement_comprehensive() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        WebhookConfig::new().with_ip_allowlist(vec![
            "192.168.1.1".into(),
            "10.0.0.0".into(),
            "::1".into(),
        ]),
    );

    assert!(handler.check_ip("192.168.1.1").is_ok());
    assert!(handler.check_ip("10.0.0.0").is_ok());
    assert!(handler.check_ip("::1").is_ok());

    assert!(matches!(
        handler.check_ip("192.168.1.2"),
        Err(WebhookError::IpNotAllowed(_))
    ));
    assert!(matches!(
        handler.check_ip("0.0.0.0"),
        Err(WebhookError::IpNotAllowed(_))
    ));
}

// ─── Payload size enforcement ─────────────────────────────────────────

#[test]
fn payload_size_enforcement_across_verifiers() {
    let verifier = HmacSha256Verifier::new("secret");
    let config = WebhookConfig::new().with_max_payload_size(64);
    let handler = WebhookHandler::with_config(verifier.clone(), "test", config);

    // Small payload passes
    let small = b"small";
    let sig = verifier.compute(small);
    assert!(handler.verify(small, &sig).is_ok());

    // Exactly 64 bytes passes
    let exact: Vec<u8> = (0..64).map(|i| b'a' + (i % 26)).collect();
    let sig = verifier.compute(&exact);
    assert!(handler.verify(&exact, &sig).is_ok());

    // 65 bytes fails
    let over: Vec<u8> = (0..65).map(|i| b'a' + (i % 26)).collect();
    assert!(matches!(
        handler.verify(&over, "ignored"),
        Err(WebhookError::PayloadTooLarge {
            size: 65,
            limit: 64
        })
    ));
}

// ─── Event payload path traversal ─────────────────────────────────────

#[test]
fn event_payload_path_traversal() {
    let event = WebhookEvent::new("e1", "push", "github").with_payload(serde_json::json!({
        "repository": {
            "full_name": "org/repo",
            "owner": {
                "login": "user",
                "id": 12345
            }
        },
        "commits": [
            {"sha": "abc123", "message": "fix bug"}
        ],
        "ref": "refs/heads/main",
        "null_field": null,
        "empty_string": ""
    }));

    assert_eq!(event.get_str("ref"), Some("refs/heads/main"));
    assert_eq!(event.get_str("repository.full_name"), Some("org/repo"));
    assert_eq!(event.get_str("repository.owner.login"), Some("user"));
    assert_eq!(event.get_i64("repository.owner.id"), Some(12345));
    assert_eq!(event.get_str("empty_string"), Some(""));
    assert_eq!(event.get_str("null_field"), None);
    assert!(event.get("nonexistent").is_none());
    assert!(event.get("repository.nonexistent").is_none());
}

// ─── Serde roundtrip stability ────────────────────────────────────────

#[test]
fn event_serde_roundtrip_preserves_all_fields() {
    let mut headers = HashMap::new();
    headers.insert("content-type".into(), "application/json".into());
    headers.insert("x-request-id".into(), "req_123".into());

    let event = WebhookEvent::new("evt_serde_1", "push", "github")
        .with_default_webhook_taint()
        .with_payload(serde_json::json!({"key": "value", "nested": {"a": 1}}))
        .with_headers(headers);

    let json = serde_json::to_string(&event).unwrap();
    let roundtrip: WebhookEvent = serde_json::from_str(&json).unwrap();

    assert_eq!(roundtrip.id, "evt_serde_1");
    assert_eq!(roundtrip.event_type, "push");
    assert_eq!(roundtrip.provider, "github");
    assert_eq!(roundtrip.get_str("key"), Some("value"));
    assert_eq!(roundtrip.get_i64("nested.a"), Some(1));
    assert_eq!(roundtrip.header("content-type"), Some("application/json"));
    assert_eq!(roundtrip.header("x-request-id"), Some("req_123"));
    assert!(
        roundtrip
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(
        roundtrip
            .metadata
            .taint_flags
            .contains(TaintFlag::PublicInput)
    );
}

// ─── WebhookProvider display ──────────────────────────────────────────

#[test]
fn webhook_provider_display_all_variants() {
    let providers = [
        (WebhookProvider::GitHub, "github"),
        (WebhookProvider::Stripe, "stripe"),
        (WebhookProvider::Slack, "slack"),
        (WebhookProvider::Linear, "linear"),
        (WebhookProvider::Discord, "discord"),
        (WebhookProvider::Custom, "custom"),
    ];

    for (provider, expected) in providers {
        assert_eq!(provider.to_string(), expected);
    }
}

// ─── Config builder patterns ──────────────────────────────────────────

#[test]
fn webhook_config_builder_all_options() {
    let config = WebhookConfig::new()
        .with_max_payload_size(1024)
        .with_idempotency(false)
        .with_idempotency_ttl(Duration::from_secs(3600))
        .with_ip_allowlist(vec!["1.2.3.4".into()])
        .with_max_retries(10);

    assert_eq!(config.max_payload_size, 1024);
    assert!(!config.idempotency_enabled);
    assert_eq!(config.idempotency_ttl, Duration::from_secs(3600));
    assert_eq!(config.ip_allowlist, vec!["1.2.3.4".to_string()]);
    assert_eq!(config.max_retries, 10);
}

#[test]
fn webhook_config_default_values() {
    let config = WebhookConfig::default();
    assert_eq!(config.max_payload_size, DEFAULT_MAX_PAYLOAD_SIZE);
    assert!(config.idempotency_enabled);
    assert_eq!(config.idempotency_ttl, Duration::from_secs(86400));
    assert!(config.ip_allowlist.is_empty());
    assert_eq!(config.max_retries, 3);
    assert_eq!(config.retry_delay, Duration::from_secs(60));
}

// ─── Constants ────────────────────────────────────────────────────────

#[test]
fn module_constants_have_expected_values() {
    assert_eq!(DEFAULT_TIMESTAMP_TOLERANCE, Duration::from_secs(300));
    assert_eq!(DEFAULT_MAX_PAYLOAD_SIZE, 5 * 1024 * 1024);
}

// ─── Signature format compatibility ───────────────────────────────────

#[test]
fn hmac_sha256_accepts_all_prefix_formats() {
    let verifier = HmacSha256Verifier::new("secret");
    let payload = b"test data";
    let raw = verifier.compute(payload);

    // No prefix
    assert!(verifier.verify(payload, &raw).is_ok());
    // sha256= prefix (GitHub)
    assert!(verifier.verify(payload, &format!("sha256={raw}")).is_ok());
    // v0= prefix (Slack)
    assert!(verifier.verify(payload, &format!("v0={raw}")).is_ok());
    // v1= prefix (Stripe)
    assert!(verifier.verify(payload, &format!("v1={raw}")).is_ok());
}

#[test]
fn hmac_sha1_accepts_sha1_prefix() {
    let verifier = HmacSha1Verifier::new("secret");
    let payload = b"test data";
    let raw = verifier.compute(payload);

    assert!(verifier.verify(payload, &raw).is_ok());
    assert!(verifier.verify(payload, &format!("sha1={raw}")).is_ok());
}

// ─── Stripe multi-signature support ───────────────────────────────────

#[test]
fn stripe_multiple_v1_signatures_any_valid_accepts() {
    let secret = "whsec_multi";
    let body = br#"{"id":"e","type":"t"}"#;
    let ts = Utc::now().timestamp();
    let signed = format!("{ts}.{}", String::from_utf8_lossy(body));
    let real_sig = HmacSha256Verifier::new(secret).compute(signed.as_bytes());

    // Multiple v1 signatures — only one needs to match
    let header = format!(
        "t={ts},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,v1={real_sig}"
    );

    let stripe = StripeWebhook::new(secret);
    let mut headers = HashMap::new();
    headers.insert("stripe-signature".into(), header);

    let event = stripe.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "e");
}

// ─── Error variant matching ──────────────────────────────────────────

#[test]
fn error_variants_display_correctly() {
    let errors: Vec<(WebhookError, &str)> = vec![
        (WebhookError::InvalidSignature, "Invalid webhook signature"),
        (
            WebhookError::MissingSignature("X-Hub-Signature".into()),
            "Missing signature header: X-Hub-Signature",
        ),
        (
            WebhookError::ReplayDetected {
                event_id: "e1".into(),
            },
            "Replay detected: event e1 already processed",
        ),
        (
            WebhookError::PayloadTooLarge {
                size: 100,
                limit: 50,
            },
            "Payload too large: 100 bytes exceeds limit of 50",
        ),
        (
            WebhookError::InvalidPayload("bad".into()),
            "Invalid payload: bad",
        ),
        (
            WebhookError::UnsupportedEventType("x".into()),
            "Unsupported event type: x",
        ),
        (
            WebhookError::ProviderNotConfigured("custom".into()),
            "Provider not configured: custom",
        ),
        (
            WebhookError::IpNotAllowed("1.2.3.4".into()),
            "IP address not in allowlist: 1.2.3.4",
        ),
        (
            WebhookError::DeliveryFailed("timeout".into()),
            "Webhook delivery failed: timeout",
        ),
    ];

    for (error, expected) in errors {
        assert_eq!(error.to_string(), expected);
    }
}

// ─── DLQ concurrent access ───────────────────────────────────────────

#[test]
fn dlq_concurrent_push_and_read() {
    let dlq = Arc::new(DeadLetterQueue::new(100));

    let mut handles = vec![];
    for i in 0..10 {
        let d = Arc::clone(&dlq);
        handles.push(thread::spawn(move || {
            d.push(WebhookEvent::new(format!("evt_{i}"), "test", "p"));
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(dlq.len(), 10);
    let all = dlq.all();
    assert_eq!(all.len(), 10);

    // All should be dead-lettered
    for event in &all {
        assert_eq!(event.metadata.status, DeliveryStatus::DeadLettered);
    }
}

// ─── Subscription matching edge cases ─────────────────────────────────

#[test]
fn subscription_complex_patterns() {
    let sub = EventSubscription::for_types(vec![
        "push".into(),
        "pull_request.*".into(),
        "issue.opened".into(),
    ])
    .with_provider("github");

    // Matches
    assert!(sub.matches(&WebhookEvent::new("e1", "push", "github")));
    assert!(sub.matches(&WebhookEvent::new("e2", "pull_request.opened", "github")));
    assert!(sub.matches(&WebhookEvent::new("e3", "pull_request.closed", "github")));
    assert!(sub.matches(&WebhookEvent::new("e4", "issue.opened", "github")));

    // Does not match
    assert!(!sub.matches(&WebhookEvent::new("e5", "issue.closed", "github")));
    assert!(!sub.matches(&WebhookEvent::new("e6", "push", "gitlab"))); // wrong provider
    assert!(!sub.matches(&WebhookEvent::new("e7", "release", "github")));
}

// ─── Header case-insensitivity in events ──────────────────────────────

#[test]
fn event_header_lookup_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert("X-Request-Id".into(), "req_abc".into());
    headers.insert("Content-Type".into(), "application/json".into());

    let event = WebhookEvent::new("e1", "test", "p").with_headers(headers);

    assert_eq!(event.header("x-request-id"), Some("req_abc"));
    assert_eq!(event.header("X-REQUEST-ID"), Some("req_abc"));
    assert_eq!(event.header("X-Request-Id"), Some("req_abc"));
    assert_eq!(event.header("content-type"), Some("application/json"));
    assert_eq!(event.header("CONTENT-TYPE"), Some("application/json"));
}

// ─── Deterministic signature vectors ──────────────────────────────────

#[test]
fn known_hmac_sha256_vectors() {
    let verifier = HmacSha256Verifier::new("secret");

    // Vector 1: empty payload
    let empty_sig = verifier.compute(b"");
    assert_eq!(empty_sig.len(), 64);
    assert!(empty_sig.chars().all(|c| c.is_ascii_hexdigit()));

    // Vector 2: known payload
    let sig = verifier.compute(b"test payload");
    assert_eq!(
        sig,
        "f1f1fc517bb886ad22c56e51dae135aad082b2e3337bed35e2e44cd299324bd8"
    );

    // Vector 3: determinism — same input always produces same output
    let sig2 = verifier.compute(b"test payload");
    assert_eq!(sig, sig2);
}

#[test]
fn known_hmac_sha1_vectors() {
    let verifier = HmacSha1Verifier::new("secret");
    let sig = verifier.compute(b"test payload");
    assert_eq!(sig.len(), 40);
    assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));

    // Determinism
    let sig2 = verifier.compute(b"test payload");
    assert_eq!(sig, sig2);
}

// ─── claim_event vs record_event semantics ────────────────────────────

#[test]
fn record_event_does_not_check_replay() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("s"), "test");

    // record_event records, never errors for fresh + duplicate inserts
    handler.record_event("evt_r1").unwrap();
    handler.record_event("evt_r1").unwrap(); // no error on duplicate

    // But check_replay now detects it
    assert!(matches!(
        handler.check_replay("evt_r1"),
        Err(WebhookError::ReplayDetected { .. })
    ));
}

#[test]
fn check_replay_does_not_record() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("s"), "test");

    // check_replay returns Ok but does NOT record
    assert!(handler.check_replay("evt_c1").is_ok());
    assert!(handler.check_replay("evt_c1").is_ok()); // still Ok — not recorded

    // Only after record_event does replay fail
    handler.record_event("evt_c1").unwrap();
    assert!(matches!(
        handler.check_replay("evt_c1"),
        Err(WebhookError::ReplayDetected { .. })
    ));
}

#[test]
fn claim_event_is_atomic_check_and_record() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("s"), "test");

    // First claim succeeds and records
    assert!(handler.claim_event("evt_a1").is_ok());

    // check_replay sees it was recorded by claim
    assert!(matches!(
        handler.check_replay("evt_a1"),
        Err(WebhookError::ReplayDetected { .. })
    ));

    // Second claim also fails
    assert!(matches!(
        handler.claim_event("evt_a1"),
        Err(WebhookError::ReplayDetected { .. })
    ));
}

// ─── Idempotency disabled full pipeline ───────────────────────────────

#[test]
fn idempotency_disabled_full_pipeline() {
    let verifier = HmacSha256Verifier::new("secret");
    let config = WebhookConfig::new().with_idempotency(false);
    let handler = WebhookHandler::with_config(verifier.clone(), "test", config);
    let mut router = EventRouter::new();
    router.subscribe(EventSubscription::all(), "catch_all");

    let github = GitHubWebhook::new("secret");
    let body = br#"{"action":"created"}"#;
    let sig = format!("sha256={}", verifier.compute(body));
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".into(), sig);
    headers.insert("x-github-event".into(), "star".into());
    headers.insert("x-github-delivery".into(), "dup_1".into());

    let event = github.verify_and_parse(&headers, body).unwrap();

    // With idempotency off, same event ID can be claimed multiple times
    assert!(handler.claim_event(&event.id).is_ok());
    assert!(handler.claim_event(&event.id).is_ok());
    assert!(handler.claim_event(&event.id).is_ok());

    // Routing still works
    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["catch_all"]);
}

// ─── Multi-provider shared DLQ ────────────────────────────────────────

#[test]
fn multi_provider_shared_dlq() {
    let dlq = DeadLetterQueue::new(10);

    // Simulate failures from different providers
    let gh_event = WebhookEvent::new("gh_fail_1", "push", "github");
    let stripe_event = WebhookEvent::new("stripe_fail_1", "charge.failed", "stripe");
    let slack_event = WebhookEvent::new("slack_fail_1", "message", "slack");

    dlq.push(gh_event);
    dlq.push(stripe_event);
    dlq.push(slack_event);

    assert_eq!(dlq.len(), 3);

    // All events get DeadLettered status
    let all = dlq.all();
    for event in &all {
        assert_eq!(event.metadata.status, DeliveryStatus::DeadLettered);
    }

    // Remove by provider-specific ID
    let removed = dlq.remove("stripe_fail_1").unwrap();
    assert_eq!(removed.provider, "stripe");
    assert_eq!(dlq.len(), 2);

    // Remaining are GitHub and Slack
    let remaining = dlq.all();
    assert_eq!(remaining[0].provider, "github");
    assert_eq!(remaining[1].provider, "slack");
}

// ─── DLQ remove + overflow interaction ────────────────────────────────

#[test]
fn dlq_remove_then_overflow() {
    let dlq = DeadLetterQueue::new(3);

    dlq.push(WebhookEvent::new("a", "t", "p"));
    dlq.push(WebhookEvent::new("b", "t", "p"));
    dlq.push(WebhookEvent::new("c", "t", "p"));
    assert_eq!(dlq.len(), 3);

    // Remove middle element
    dlq.remove("b");
    assert_eq!(dlq.len(), 2);

    // Push two more — now at capacity (3), no eviction needed for first
    dlq.push(WebhookEvent::new("d", "t", "p"));
    assert_eq!(dlq.len(), 3);

    // One more triggers eviction of oldest ("a")
    dlq.push(WebhookEvent::new("e", "t", "p"));
    assert_eq!(dlq.len(), 3);

    let all = dlq.all();
    let ids: Vec<&str> = all.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, vec!["c", "d", "e"]);
}

// ─── DLQ all() returns clones (mutation safety) ───────────────────────

#[test]
fn dlq_all_returns_independent_clones() {
    let dlq = DeadLetterQueue::new(10);
    dlq.push(WebhookEvent::new("x", "test", "p"));

    let snapshot1 = dlq.all();
    assert_eq!(snapshot1.len(), 1);

    // Push another event after taking snapshot
    dlq.push(WebhookEvent::new("y", "test", "p"));

    // Original snapshot is unchanged
    assert_eq!(snapshot1.len(), 1);
    assert_eq!(dlq.len(), 2);
}

// ─── Stripe timestamp edge cases ──────────────────────────────────────

#[test]
fn stripe_rejects_far_future_timestamp() {
    let secret = "whsec_future";
    let stripe = StripeWebhook::new(secret).with_timestamp_tolerance(Duration::from_secs(60));

    let body = br#"{"id":"e","type":"t"}"#;
    // Timestamp 1 hour in the future
    let future_ts = Utc::now().timestamp() + 3600;
    let signed = format!("{future_ts}.{}", String::from_utf8_lossy(body));
    let sig = HmacSha256Verifier::new(secret).compute(signed.as_bytes());

    let mut headers = HashMap::new();
    headers.insert("stripe-signature".into(), format!("t={future_ts},v1={sig}"));

    let result = stripe.verify_and_parse(&headers, body);
    assert!(matches!(
        result,
        Err(WebhookError::TimestampValidation { .. })
    ));
}

#[test]
fn stripe_accepts_timestamp_within_tolerance() {
    let secret = "whsec_tolerance";
    let stripe = StripeWebhook::new(secret).with_timestamp_tolerance(Duration::from_secs(300));

    let body = br#"{"id":"evt_ok","type":"invoice.paid"}"#;
    // 2 seconds ago — well within tolerance
    let ts = Utc::now().timestamp() - 2;
    let signed = format!("{ts}.{}", String::from_utf8_lossy(body));
    let sig = HmacSha256Verifier::new(secret).compute(signed.as_bytes());

    let mut headers = HashMap::new();
    headers.insert("stripe-signature".into(), format!("t={ts},v1={sig}"));

    let event = stripe.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "evt_ok");
    assert_eq!(event.event_type, "invoice.paid");
}

// ─── Error From impls at integration level ────────────────────────────

#[test]
fn json_error_from_impl_integration() {
    let result: Result<serde_json::Value, _> = serde_json::from_str("{bad json}");
    let webhook_err: WebhookError = result.unwrap_err().into();
    assert!(matches!(webhook_err, WebhookError::JsonError(_)));
    assert!(webhook_err.to_string().starts_with("JSON parsing error:"));
}

#[test]
fn hex_error_from_impl_integration() {
    let result = hex::decode("not-valid-hex");
    let webhook_err: WebhookError = result.unwrap_err().into();
    assert!(matches!(webhook_err, WebhookError::HexError(_)));
    assert!(webhook_err.to_string().starts_with("Hex decoding error:"));
}

// ─── WebhookError is Send + Sync + std::error::Error ──────────────────

#[test]
fn webhook_error_trait_bounds() {
    fn assert_send_sync<T: Send + Sync + std::error::Error>() {}
    assert_send_sync::<WebhookError>();
}

// ─── Cross-provider signature isolation ───────────────────────────────

#[test]
fn cross_provider_signatures_do_not_leak() {
    let gh_secret = "github_secret_123";
    let stripe_secret = "stripe_secret_456";

    let github = GitHubWebhook::new(gh_secret);
    let stripe = StripeWebhook::new(stripe_secret);

    let body = br#"{"action":"opened"}"#;

    // GitHub signature signed with stripe secret fails on GitHub handler
    let wrong_sig = format!(
        "sha256={}",
        HmacSha256Verifier::new(stripe_secret).compute(body)
    );
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".into(), wrong_sig);
    headers.insert("x-github-event".into(), "issues".into());
    assert!(github.verify_and_parse(&headers, body).is_err());

    // Correct GitHub signature works
    let correct_sig = format!(
        "sha256={}",
        HmacSha256Verifier::new(gh_secret).compute(body)
    );
    headers.insert("x-hub-signature-256".into(), correct_sig);
    assert!(github.verify_and_parse(&headers, body).is_ok());

    // Stripe signed with github secret fails on Stripe handler
    let body = br#"{"id":"e","type":"t"}"#;
    let ts = Utc::now().timestamp();
    let signed = format!("{ts}.{}", String::from_utf8_lossy(body));
    let wrong_sig = HmacSha256Verifier::new(gh_secret).compute(signed.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("stripe-signature".into(), format!("t={ts},v1={wrong_sig}"));
    assert!(stripe.verify_and_parse(&headers, body).is_err());
}

// ─── Event matches_type wildcard edge cases ───────────────────────────

#[test]
fn matches_type_trailing_wildcard_behavior() {
    let event = WebhookEvent::new("e1", "issue.opened", "gh");

    // "issue.*" matches (prefix "issue." matches start)
    assert!(event.matches_type("issue.*"));
    // "issue.opened*" matches (prefix "issue.opened" matches start)
    assert!(event.matches_type("issue.opened*"));
    // "*" matches everything
    assert!(event.matches_type("*"));
    // "i*" matches (prefix "i" matches start)
    assert!(event.matches_type("i*"));
    // "issue.close*" does not match
    assert!(!event.matches_type("issue.close*"));
    // Exact match works
    assert!(event.matches_type("issue.opened"));
    // Extra suffix fails exact
    assert!(!event.matches_type("issue.opened.extra"));
}

#[test]
fn matches_type_wildcard_on_empty_event_type() {
    let event = WebhookEvent::new("e1", "", "gh");
    assert!(event.matches_type("*"));
    assert!(event.matches_type(""));
    assert!(!event.matches_type("push"));
    // "*" as trailing wildcard with empty prefix matches everything
    assert!(event.matches_type("*"));
}

// ─── Router subscription ordering ────────────────────────────────────

#[test]
fn router_preserves_subscription_order_in_results() {
    let mut router = EventRouter::new();
    router.subscribe(EventSubscription::all(), "handler_a");
    router.subscribe(EventSubscription::all(), "handler_b");
    router.subscribe(EventSubscription::all(), "handler_c");

    let event = WebhookEvent::new("e1", "push", "github");
    let handlers = router.route(&event);

    // Results should be in subscription order
    assert_eq!(handlers, vec!["handler_a", "handler_b", "handler_c"]);
}

#[test]
fn router_same_handler_id_multiple_subscriptions() {
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["push".into()]),
        "my_handler",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["issue.*".into()]),
        "my_handler",
    );

    let event = WebhookEvent::new("e1", "push", "github");
    let handlers = router.route(&event);
    // Same handler matched once via push pattern
    assert_eq!(handlers, vec!["my_handler"]);

    let event2 = WebhookEvent::new("e2", "issue.opened", "github");
    let handlers2 = router.route(&event2);
    assert_eq!(handlers2, vec!["my_handler"]);
}

// ─── EventMetadata custom fields through pipeline ─────────────────────

#[test]
fn event_metadata_custom_fields_survive_serde() {
    let mut custom = HashMap::new();
    custom.insert("retry_count".into(), serde_json::json!(3));
    custom.insert("region".into(), serde_json::json!("us-east-1"));

    let mut event = WebhookEvent::new("evt_custom", "push", "github");
    event.metadata = fcp_webhook::EventMetadata {
        attempt: 2,
        status: DeliveryStatus::Failed,
        last_error: Some("connection timeout".into()),
        source_ip: Some("10.0.0.5".into()),
        custom,
        ..Default::default()
    };

    let json = serde_json::to_string(&event).unwrap();
    let roundtrip: WebhookEvent = serde_json::from_str(&json).unwrap();

    assert_eq!(roundtrip.metadata.attempt, 2);
    assert_eq!(roundtrip.metadata.status, DeliveryStatus::Failed);
    assert_eq!(
        roundtrip.metadata.last_error.as_deref(),
        Some("connection timeout")
    );
    assert_eq!(roundtrip.metadata.source_ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(
        roundtrip.metadata.custom.get("retry_count"),
        Some(&serde_json::json!(3))
    );
    assert_eq!(
        roundtrip.metadata.custom.get("region"),
        Some(&serde_json::json!("us-east-1"))
    );
}

// ─── DLQ status transition ───────────────────────────────────────────

#[test]
fn dlq_overrides_status_to_dead_lettered() {
    let dlq = DeadLetterQueue::new(10);

    // Create event with Delivered status
    let mut event = WebhookEvent::new("evt_status", "push", "github");
    event.metadata.status = DeliveryStatus::Delivered;

    // DLQ should override to DeadLettered
    dlq.push(event);
    let retrieved = dlq.all();
    assert_eq!(retrieved[0].metadata.status, DeliveryStatus::DeadLettered);
}

// ─── Ed25519 verifier from_hex in full pipeline ──────────────────────

#[test]
fn ed25519_from_hex_full_pipeline() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let verifier = Ed25519Verifier::from_hex(&pub_hex).unwrap();

    // Use in a WebhookHandler
    let handler = WebhookHandler::new(verifier, "discord");
    assert_eq!(handler.provider(), "discord");
    assert_eq!(handler.config().max_payload_size, DEFAULT_MAX_PAYLOAD_SIZE);

    // Verify a payload
    let body = b"discord webhook body";
    let sig = signing_key.sign(body);
    let sig_hex = hex::encode(sig.to_bytes());
    assert!(handler.verify(body, &sig_hex).is_ok());

    // Wrong signature fails
    assert!(handler.verify(body, &"00".repeat(64)).is_err());
}

// ─── Empty IP allowlist allows everything ─────────────────────────────

#[test]
fn empty_ip_allowlist_permits_all_ips() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("s"), "test");

    // No allowlist configured → all IPs allowed
    assert!(handler.check_ip("192.168.0.1").is_ok());
    assert!(handler.check_ip("0.0.0.0").is_ok());
    assert!(handler.check_ip("::1").is_ok());
    assert!(handler.check_ip("fd00::1").is_ok());
    assert!(handler.check_ip("anything").is_ok());
}

// ─── Signature algorithm display ──────────────────────────────────────

#[test]
fn signature_algorithm_display_all_variants() {
    assert_eq!(SignatureAlgorithm::HmacSha256.to_string(), "HMAC-SHA256");
    assert_eq!(SignatureAlgorithm::HmacSha1.to_string(), "HMAC-SHA1");
    assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "Ed25519");
}

// ─── Full multi-provider pipeline end-to-end ──────────────────────────

#[test]
fn multi_provider_pipeline_end_to_end() {
    // Setup: handler, router, DLQ
    let handler = WebhookHandler::new(HmacSha256Verifier::new("shared"), "multi");
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::all().with_provider("github"),
        "github_sync",
    );
    router.subscribe(
        EventSubscription::all().with_provider("linear"),
        "linear_sync",
    );
    router.subscribe(
        EventSubscription::for_types(vec!["payment_intent.*".into()]),
        "billing",
    );
    let dlq = DeadLetterQueue::new(100);

    // GitHub event
    let gh = GitHubWebhook::new("gh_secret");
    let gh_body = br#"{"action":"opened"}"#;
    let gh_sig = format!(
        "sha256={}",
        HmacSha256Verifier::new("gh_secret").compute(gh_body)
    );
    let mut gh_headers = HashMap::new();
    gh_headers.insert("x-hub-signature-256".into(), gh_sig);
    gh_headers.insert("x-github-event".into(), "issues".into());
    gh_headers.insert("x-github-delivery".into(), "gh_del_1".into());
    let gh_event = gh.verify_and_parse(&gh_headers, gh_body).unwrap();
    assert!(handler.claim_event(&gh_event.id).is_ok());
    let gh_handlers = router.route(&gh_event);
    assert_eq!(gh_handlers, vec!["github_sync"]);

    // Linear event
    let ln = LinearWebhook::new("ln_secret");
    let ln_body = br#"{"type":"Issue","webhookId":"wh_ln_1"}"#;
    let ln_sig = HmacSha256Verifier::new("ln_secret").compute(ln_body);
    let mut ln_headers = HashMap::new();
    ln_headers.insert("linear-signature".into(), ln_sig);
    let ln_event = ln.verify_and_parse(&ln_headers, ln_body).unwrap();
    assert!(handler.claim_event(&ln_event.id).is_ok());
    let ln_handlers = router.route(&ln_event);
    assert_eq!(ln_handlers, vec!["linear_sync"]);

    // Simulate failure → DLQ
    let failed = WebhookEvent::new("failed_delivery", "push", "github");
    dlq.push(failed);
    assert_eq!(dlq.len(), 1);
    assert_eq!(dlq.all()[0].metadata.status, DeliveryStatus::DeadLettered);
}

// ─── Timestamp error contains all fields ──────────────────────────────

#[test]
fn timestamp_error_fields_populated() {
    let stripe = StripeWebhook::new("s").with_timestamp_tolerance(Duration::from_secs(10));
    let body = br#"{"id":"e","type":"t"}"#;
    let old_ts = 1_000_000_000_i64;
    let signed = format!("{old_ts}.{}", String::from_utf8_lossy(body));
    let sig = HmacSha256Verifier::new("s").compute(signed.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("stripe-signature".into(), format!("t={old_ts},v1={sig}"));

    match stripe.verify_and_parse(&headers, body) {
        Err(WebhookError::TimestampValidation {
            reason,
            timestamp,
            current_time,
            tolerance,
        }) => {
            assert!(!reason.is_empty());
            assert_eq!(timestamp, Some(old_ts));
            assert!(current_time > old_ts);
            assert_eq!(tolerance, Duration::from_secs(10));
        }
        other => panic!("Expected TimestampValidation, got {other:?}"),
    }
}

// ─── Provider error paths: malformed inputs ────────────────────────────

#[test]
fn github_missing_signature_header() {
    let gh = GitHubWebhook::new("secret");
    let body = br#"{"action":"push"}"#;
    let headers = HashMap::new(); // no headers at all
    let err = gh.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::MissingSignature(_)));
}

#[test]
fn github_wrong_signature_rejected() {
    let gh = GitHubWebhook::new("secret");
    let body = br#"{"action":"push"}"#;
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".to_string(), "sha256=0000".to_string());
    headers.insert("x-github-event".to_string(), "push".to_string());
    let err = gh.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

#[test]
fn github_invalid_json_body() {
    let gh = GitHubWebhook::new("secret");
    let body = b"not json";
    let sig = HmacSha256Verifier::new("secret").compute(body);
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".to_string(), format!("sha256={sig}"));
    headers.insert("x-github-event".to_string(), "push".to_string());
    let err = gh.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::JsonError(_)));
}

#[test]
fn github_missing_event_type_defaults_to_unknown() {
    let gh = GitHubWebhook::new("secret");
    let body = br#"{"action":"opened"}"#;
    let sig = HmacSha256Verifier::new("secret").compute(body);
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".to_string(), format!("sha256={sig}"));
    // no x-github-event header
    let event = gh.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.event_type, "unknown");
}

#[test]
fn github_missing_delivery_id_generates_uuid() {
    let gh = GitHubWebhook::new("secret");
    let body = br#"{"action":"opened"}"#;
    let sig = HmacSha256Verifier::new("secret").compute(body);
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".to_string(), format!("sha256={sig}"));
    headers.insert("x-github-event".to_string(), "push".to_string());
    // no x-github-delivery header
    let event = gh.verify_and_parse(&headers, body).unwrap();
    assert!(!event.id.is_empty());
    assert_ne!(event.id, "unknown");
}

#[test]
fn stripe_missing_signature_header() {
    let stripe = StripeWebhook::new("secret");
    let body = br#"{"id":"e","type":"t"}"#;
    let headers = HashMap::new();
    let err = stripe.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::MissingSignature(_)));
}

#[test]
fn stripe_malformed_signature_no_v1() {
    let stripe = StripeWebhook::new("secret");
    let body = br#"{"id":"e","type":"t"}"#;
    let mut headers = HashMap::new();
    headers.insert("stripe-signature".to_string(), "t=12345".to_string());
    let err = stripe.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidPayload(_)));
}

#[test]
fn stripe_malformed_signature_no_timestamp() {
    let stripe = StripeWebhook::new("secret");
    let body = br#"{"id":"e","type":"t"}"#;
    let mut headers = HashMap::new();
    headers.insert("stripe-signature".to_string(), "v1=abcdef".to_string());
    let err = stripe.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidPayload(_)));
}

#[test]
fn stripe_invalid_json_body() {
    let stripe = StripeWebhook::new("secret");
    let body = b"not json";
    let ts = Utc::now().timestamp();
    let signed = format!("{ts}.{}", String::from_utf8_lossy(body));
    let sig = HmacSha256Verifier::new("secret").compute(signed.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("stripe-signature".to_string(), format!("t={ts},v1={sig}"));
    let err = stripe.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::JsonError(_)));
}

#[test]
fn slack_missing_signature_header() {
    let slack = SlackWebhook::new("secret");
    let body = br#"{"type":"event"}"#;
    let mut headers = HashMap::new();
    headers.insert(
        "x-slack-request-timestamp".to_string(),
        Utc::now().timestamp().to_string(),
    );
    let err = slack.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::MissingSignature(_)));
}

#[test]
fn slack_missing_timestamp_header() {
    let slack = SlackWebhook::new("secret");
    let body = br#"{"type":"event"}"#;
    let mut headers = HashMap::new();
    headers.insert("x-slack-signature".to_string(), "v0=abc".to_string());
    let err = slack.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::MissingSignature(_)));
}

#[test]
fn slack_non_numeric_timestamp() {
    let slack = SlackWebhook::new("secret");
    let body = br#"{"type":"event"}"#;
    let mut headers = HashMap::new();
    headers.insert("x-slack-signature".to_string(), "v0=abc".to_string());
    headers.insert(
        "x-slack-request-timestamp".to_string(),
        "not-a-number".to_string(),
    );
    let err = slack.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidPayload(_)));
}

#[test]
fn linear_missing_signature_header() {
    let linear = LinearWebhook::new("secret");
    let body = br#"{"type":"issue"}"#;
    let headers = HashMap::new();
    let err = linear.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::MissingSignature(_)));
}

#[test]
fn linear_wrong_signature() {
    let linear = LinearWebhook::new("secret");
    let body = br#"{"type":"issue"}"#;
    let mut headers = HashMap::new();
    headers.insert("linear-signature".to_string(), "0000dead".to_string());
    let err = linear.verify_and_parse(&headers, body).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

// ─── Payload size enforcement order ────────────────────────────────────

#[test]
fn handler_rejects_oversized_payload_before_sig_check() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("secret"),
        "test",
        WebhookConfig::new().with_max_payload_size(10),
    );
    // 20-byte payload, invalid signature — should fail with PayloadTooLarge, not InvalidSig
    let big = vec![b'x'; 20];
    let err = handler.verify(&big, "invalid-sig").unwrap_err();
    assert!(matches!(
        err,
        WebhookError::PayloadTooLarge {
            size: 20,
            limit: 10
        }
    ));
}

#[test]
fn handler_payload_at_exact_limit_passes_size_check() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("secret"),
        "test",
        WebhookConfig::new().with_max_payload_size(10),
    );
    let body = vec![b'x'; 10];
    let sig = HmacSha256Verifier::new("secret").compute(&body);
    // Should pass size check, then pass sig check
    assert!(handler.verify(&body, &sig).is_ok());
}

#[test]
fn handler_payload_one_over_limit_rejected() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("secret"),
        "test",
        WebhookConfig::new().with_max_payload_size(10),
    );
    let body = vec![b'x'; 11];
    let err = handler.verify(&body, "whatever").unwrap_err();
    assert!(matches!(
        err,
        WebhookError::PayloadTooLarge {
            size: 11,
            limit: 10
        }
    ));
}

// ─── IP allowlist edge cases ───────────────────────────────────────────

#[test]
fn ip_allowlist_empty_permits_all() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        WebhookConfig::new().with_ip_allowlist(vec![]),
    );
    assert!(handler.check_ip("1.2.3.4").is_ok());
    assert!(handler.check_ip("::1").is_ok());
    assert!(handler.check_ip("anything").is_ok());
}

#[test]
fn ip_allowlist_exact_match_required() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        WebhookConfig::new()
            .with_ip_allowlist(vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()]),
    );
    assert!(handler.check_ip("192.168.1.1").is_ok());
    assert!(handler.check_ip("10.0.0.1").is_ok());
    assert!(handler.check_ip("192.168.1.2").is_err());
    assert!(handler.check_ip("").is_err());
}

#[test]
fn ip_allowlist_ipv6_address() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        WebhookConfig::new().with_ip_allowlist(vec!["::1".to_string(), "2001:db8::1".to_string()]),
    );
    assert!(handler.check_ip("::1").is_ok());
    assert!(handler.check_ip("2001:db8::1").is_ok());
    assert!(handler.check_ip("::2").is_err());
}

#[test]
fn ip_allowlist_whitespace_not_trimmed() {
    // IP matching is exact string comparison — leading/trailing space matters
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        WebhookConfig::new().with_ip_allowlist(vec!["10.0.0.1".to_string()]),
    );
    assert!(handler.check_ip("10.0.0.1").is_ok());
    assert!(handler.check_ip(" 10.0.0.1").is_err());
    assert!(handler.check_ip("10.0.0.1 ").is_err());
}

// ─── Idempotency edge cases ───────────────────────────────────────────

#[test]
fn idempotency_disabled_allows_duplicates() {
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        WebhookConfig::new().with_idempotency(false),
    );
    assert!(handler.claim_event("evt-1").is_ok());
    assert!(handler.claim_event("evt-1").is_ok()); // no rejection
    assert!(handler.check_replay("evt-1").is_ok()); // no rejection
}

#[test]
fn record_then_check_replay_detects() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("s"), "test");
    handler.record_event("evt-1").unwrap();
    let err = handler.check_replay("evt-1").unwrap_err();
    assert!(matches!(err, WebhookError::ReplayDetected { .. }));
}

// ─── Algorithm switching & verifier isolation ──────────────────────────

#[test]
fn handler_with_hmac_sha1_verifier() {
    let verifier = HmacSha1Verifier::new("secret");
    let handler = WebhookHandler::new(verifier.clone(), "test-sha1");
    let body = b"test payload";
    let sig = verifier.compute(body);
    assert!(handler.verify(body, &sig).is_ok());
    assert_eq!(handler.provider(), "test-sha1");
}

#[test]
fn hmac_sha256_rejects_sha1_signature() {
    let sha256_handler = WebhookHandler::new(HmacSha256Verifier::new("secret"), "test");
    let sha1_sig = HmacSha1Verifier::new("secret").compute(b"payload");
    let err = sha256_handler.verify(b"payload", &sha1_sig).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

#[test]
fn verifier_algorithm_reports_correct_type() {
    assert_eq!(
        HmacSha256Verifier::new("s").algorithm(),
        SignatureAlgorithm::HmacSha256
    );
    assert_eq!(
        HmacSha1Verifier::new("s").algorithm(),
        SignatureAlgorithm::HmacSha1
    );
}

// ─── Cross-provider isolation ──────────────────────────────────────────

#[test]
fn different_secrets_reject_each_other() {
    let gh_a = GitHubWebhook::new("secret-A");
    let gh_b = GitHubWebhook::new("secret-B");
    let body = br#"{"action":"push"}"#;

    // Sign with A's secret
    let sig_a = HmacSha256Verifier::new("secret-A").compute(body);
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".to_string(), format!("sha256={sig_a}"));
    headers.insert("x-github-event".to_string(), "push".to_string());

    // A accepts
    assert!(gh_a.verify_and_parse(&headers, body).is_ok());
    // B rejects
    assert!(gh_b.verify_and_parse(&headers, body).is_err());
}

// ─── Router dedup & ordering ───────────────────────────────────────────

#[test]
fn router_same_handler_multiple_matching_subs_routes_once() {
    let mut router = EventRouter::new();
    router.subscribe(EventSubscription::for_types(vec!["push".into()]), "ci");
    router.subscribe(EventSubscription::all(), "ci"); // also matches

    let event = WebhookEvent::new("1", "push", "github");
    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["ci"]);
}

#[test]
fn router_no_subscriptions_returns_empty() {
    let router = EventRouter::new();
    let event = WebhookEvent::new("1", "push", "github");
    assert!(router.route(&event).is_empty());
}

// ─── DLQ: remove & clear ──────────────────────────────────────────────

#[test]
fn dlq_remove_returns_event() {
    let dlq = DeadLetterQueue::new(10);
    dlq.push(WebhookEvent::new("a", "t", "p"));
    dlq.push(WebhookEvent::new("b", "t", "p"));

    let removed = dlq.remove("a");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, "a");
    assert_eq!(dlq.len(), 1);
}

#[test]
fn dlq_remove_nonexistent_returns_none() {
    let dlq = DeadLetterQueue::new(10);
    dlq.push(WebhookEvent::new("a", "t", "p"));
    assert!(dlq.remove("nonexistent").is_none());
    assert_eq!(dlq.len(), 1);
}

#[test]
fn dlq_clear_empties_queue() {
    let dlq = DeadLetterQueue::new(10);
    dlq.push(WebhookEvent::new("a", "t", "p"));
    dlq.push(WebhookEvent::new("b", "t", "p"));
    dlq.push(WebhookEvent::new("c", "t", "p"));
    assert_eq!(dlq.len(), 3);

    dlq.clear();
    assert!(dlq.is_empty());
    assert_eq!(dlq.len(), 0);
}

// ─── Event metadata & taint ────────────────────────────────────────────

#[test]
fn event_multiple_taint_flags() {
    let event = WebhookEvent::new("1", "push", "github")
        .with_taint_flag(TaintFlag::WebhookInjected)
        .with_taint_flag(TaintFlag::PublicInput)
        .with_taint_flag(TaintFlag::UntrustedTransform);

    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::UntrustedTransform)
    );
}

#[test]
fn event_default_webhook_taint_idempotent() {
    let event = WebhookEvent::new("1", "t", "p")
        .with_default_webhook_taint()
        .with_default_webhook_taint(); // applying twice

    assert!(
        event
            .metadata
            .taint_flags
            .contains(TaintFlag::WebhookInjected)
    );
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
}

#[test]
fn delivery_status_serde_roundtrip() {
    let statuses = vec![
        DeliveryStatus::Pending,
        DeliveryStatus::Delivered,
        DeliveryStatus::Failed,
        DeliveryStatus::DeadLettered,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let back: DeliveryStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

// ─── Full error pipeline: handler verify → route → DLQ ────────────────

#[test]
fn pipeline_invalid_sig_skips_routing_and_dlq() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("secret"), "github");
    let router = EventRouter::new();
    let dlq = DeadLetterQueue::new(10);

    // Invalid signature
    let err = handler.verify(b"body", "bad-sig");
    assert!(err.is_err());

    // Since verification failed, no event to route or DLQ
    // This tests the expected flow: error stops pipeline
    assert!(dlq.is_empty());
    assert!(router.route(&WebhookEvent::new("x", "t", "p")).is_empty());
}

#[test]
fn pipeline_replay_detected_does_not_create_duplicate_events() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("secret"), "github");

    // Claim event once
    handler.claim_event("evt-1").unwrap();

    // Second claim returns ReplayDetected
    let err = handler.claim_event("evt-1").unwrap_err();
    assert!(matches!(err, WebhookError::ReplayDetected { event_id } if event_id == "evt-1"));
}

// ─── WebhookProvider enum coverage ─────────────────────────────────────

#[test]
fn webhook_provider_display_roundtrip() {
    assert_eq!(WebhookProvider::GitHub.to_string(), "github");
    assert_eq!(WebhookProvider::Stripe.to_string(), "stripe");
    assert_eq!(WebhookProvider::Slack.to_string(), "slack");
    assert_eq!(WebhookProvider::Linear.to_string(), "linear");
    assert_eq!(WebhookProvider::Discord.to_string(), "discord");
    assert_eq!(WebhookProvider::Custom.to_string(), "custom");
}

#[test]
fn webhook_provider_copy_and_eq() {
    let a = WebhookProvider::GitHub;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(WebhookProvider::GitHub, WebhookProvider::Stripe);
}

// ─── Handler accessors & Debug ─────────────────────────────────────────

#[test]
fn handler_provider_and_config_accessors() {
    let config = WebhookConfig::new()
        .with_max_payload_size(1024)
        .with_max_retries(5)
        .with_idempotency(false);
    let handler =
        WebhookHandler::with_config(HmacSha256Verifier::new("s"), "custom-provider", config);

    assert_eq!(handler.provider(), "custom-provider");
    assert_eq!(handler.config().max_payload_size, 1024);
    assert_eq!(handler.config().max_retries, 5);
    assert!(!handler.config().idempotency_enabled);
}

#[test]
fn handler_debug_does_not_leak_secret() {
    let handler = WebhookHandler::new(HmacSha256Verifier::new("super-secret-key"), "test");
    let debug = format!("{handler:?}");
    assert!(!debug.contains("super-secret-key"));
}

// ─── Concurrent handler sharing (Send + Sync via Arc) ──────────────────

#[test]
#[allow(clippy::similar_names)]
fn handler_shared_across_threads() {
    let handler = Arc::new(WebhookHandler::new(
        HmacSha256Verifier::new("secret"),
        "test",
    ));

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let h = Arc::clone(&handler);
            thread::spawn(move || {
                h.claim_event(&format!("evt-{i}")).unwrap();
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // All 4 events should now be replay-detected
    for i in 0..4 {
        assert!(handler.claim_event(&format!("evt-{i}")).is_err());
    }
}
