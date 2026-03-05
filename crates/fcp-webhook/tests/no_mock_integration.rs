//! No-mock integration tests for fcp-webhook.
//!
//! These tests exercise the full webhook pipeline (signature verification,
//! event parsing, routing, dead letter queue) without any external mocks.

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
    DeadLetterQueue, DeliveryStatus, Ed25519Verifier, EventRouter, EventSubscription,
    GitHubWebhook, HmacSha1Verifier, HmacSha256Verifier, LinearWebhook, SignatureAlgorithm,
    SignatureVerifier, SlackWebhook, StripeWebhook, WebhookConfig, WebhookError, WebhookEvent,
    WebhookHandler, WebhookProvider, DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_TIMESTAMP_TOLERANCE,
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
    router.subscribe(EventSubscription::all().with_provider("github"), "audit_log");
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
    let sig = format!(
        "sha256={}",
        HmacSha256Verifier::new("secret").compute(body)
    );
    let mut headers = HashMap::new();
    headers.insert("x-hub-signature-256".into(), sig);
    headers.insert("x-github-event".into(), "push".into());
    headers.insert("x-github-delivery".into(), "del_push_1".into());

    let event = github.verify_and_parse(&headers, body).unwrap();
    let handlers = router.route(&event);
    assert_eq!(handlers, vec!["ci_trigger"]);
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
    headers.insert(
        "x-slack-request-timestamp".into(),
        timestamp.to_string(),
    );

    let event = slack.verify_and_parse(&headers, body).unwrap();
    assert_eq!(event.id, "Ev_slack_1");
    // Slack uses top-level "type" first, which is "event_callback"
    assert_eq!(event.event_type, "event_callback");
    assert_eq!(event.provider, "slack");

    // event_callback doesn't match "message" or "url_verification"
    let handlers = router.route(&event);
    assert!(handlers.is_empty());
}

#[test]
fn pipeline_linear_verify_and_route() {
    let linear = LinearWebhook::new("linear_secret");
    let mut router = EventRouter::new();
    router.subscribe(
        EventSubscription::for_types(vec!["Issue".into()]),
        "issue_sync",
    );

    let body = br#"{"type":"Issue","action":"create","webhookId":"wh_lin_1","data":{"title":"Bug fix"}}"#;
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
        dlq.push(WebhookEvent::new(
            format!("evt_{i}"),
            "test",
            "provider",
        ));
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
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
        0x1c, 0xae, 0x7f, 0x60,
    ]);
    let verifier =
        Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();

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
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
        0x1c, 0xae, 0x7f, 0x60,
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
    assert!(event.metadata.taint_flags.contains(TaintFlag::WebhookInjected));
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));

    // Linear
    let ln = LinearWebhook::new("s");
    let body = br#"{"type":"Issue"}"#;
    let sig = HmacSha256Verifier::new("s").compute(body);
    let mut h = HashMap::new();
    h.insert("linear-signature".into(), sig);
    let event = ln.verify_and_parse(&h, body).unwrap();
    assert!(event.metadata.taint_flags.contains(TaintFlag::WebhookInjected));
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
    assert!(event.metadata.taint_flags.contains(TaintFlag::WebhookInjected));
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
    assert!(event.metadata.taint_flags.contains(TaintFlag::WebhookInjected));
    assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
}

// ─── Replay protection with TTL expiry ────────────────────────────────

#[test]
fn replay_protection_ttl_lifecycle() {
    let config = WebhookConfig::new()
        .with_idempotency(true)
        .with_idempotency_ttl(Duration::from_millis(50));
    let handler = WebhookHandler::with_config(
        HmacSha256Verifier::new("s"),
        "test",
        config,
    );

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
    assert_eq!(
        event.get_str("repository.full_name"),
        Some("org/repo")
    );
    assert_eq!(
        event.get_str("repository.owner.login"),
        Some("user")
    );
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
    assert!(roundtrip.metadata.taint_flags.contains(TaintFlag::WebhookInjected));
    assert!(roundtrip.metadata.taint_flags.contains(TaintFlag::PublicInput));
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
    let header = format!("t={ts},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,v1={real_sig}");

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
