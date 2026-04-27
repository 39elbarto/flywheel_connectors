#![no_main]
//! Fuzz target for provider-specific webhook signature header parsers.
//!
//! Complements `fuzz_webhook_signature` by driving the public provider entry
//! points that parse attacker-controlled header grammars before the raw HMAC
//! verifier runs:
//!
//! - Stripe `Stripe-Signature`: `t=...,v1=...[,v1=...]`
//! - Slack `X-Slack-Signature` + `X-Slack-Request-Timestamp`
//! - GitHub `X-Hub-Signature-256`
//! - Linear `Linear-Signature`
//!
//! The harness asserts only bounded positive invariants and otherwise treats
//! every provider result as data: malformed headers must never panic, and a
//! correctly signed payload must continue to verify successfully.

use std::collections::HashMap;

use arbitrary::{Arbitrary, Unstructured};
use chrono::Utc;
use fcp_webhook::{
    GitHubWebhook, HmacSha256Verifier, LinearWebhook, SlackWebhook, StripeWebhook,
};
use libfuzzer_sys::fuzz_target;

const MAX_BODY_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 512;
const MAX_ID_BYTES: usize = 128;
const MAX_STRIPE_SIGS: usize = 12;
const SHARED_SECRET: &[u8] = b"fuzz-webhook-provider-secret";

#[derive(Arbitrary, Debug)]
struct ProviderHeaderFuzz<'a> {
    signature_header: &'a [u8],
    timestamp_header: Option<&'a [u8]>,
    body: &'a [u8],
    event_type: &'a [u8],
    delivery_id: &'a [u8],
    duplicate_signature_header: bool,
    duplicate_timestamp_header: bool,
    stripe_signatures: Vec<&'a [u8]>,
}

fn bounded_bytes<'a>(bytes: &'a [u8], max: usize) -> &'a [u8] {
    &bytes[..bytes.len().min(max)]
}

fn lossy_header(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bounded_bytes(bytes, MAX_HEADER_BYTES)).into_owned()
}

fn lossy_id(bytes: &[u8], fallback: &str) -> String {
    let raw = String::from_utf8_lossy(bounded_bytes(bytes, MAX_ID_BYTES));
    let cleaned: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_ID_BYTES)
        .collect();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

fn bounded_body(bytes: &[u8]) -> Vec<u8> {
    bounded_bytes(bytes, MAX_BODY_BYTES).to_vec()
}

fn insert_header(
    headers: &mut HashMap<String, String>,
    name: &str,
    value: String,
    duplicate_case_variant: bool,
) {
    headers.insert(name.to_string(), value.clone());
    if duplicate_case_variant {
        headers.insert(name.to_ascii_uppercase(), value);
    }
}

fn exercise_github_negative(input: &ProviderHeaderFuzz<'_>) {
    let mut headers = HashMap::new();
    insert_header(
        &mut headers,
        "x-hub-signature-256",
        lossy_header(input.signature_header),
        input.duplicate_signature_header,
    );
    headers.insert(
        "x-github-event".to_string(),
        lossy_id(input.event_type, "push"),
    );
    headers.insert(
        "x-github-delivery".to_string(),
        lossy_id(input.delivery_id, "delivery"),
    );
    let _ = GitHubWebhook::new(SHARED_SECRET).verify_and_parse(&headers, &bounded_body(input.body));
}

fn exercise_linear_negative(input: &ProviderHeaderFuzz<'_>) {
    let mut headers = HashMap::new();
    insert_header(
        &mut headers,
        "linear-signature",
        lossy_header(input.signature_header),
        input.duplicate_signature_header,
    );
    let _ = LinearWebhook::new(SHARED_SECRET).verify_and_parse(&headers, &bounded_body(input.body));
}

fn exercise_slack_negative(input: &ProviderHeaderFuzz<'_>) {
    let mut headers = HashMap::new();
    insert_header(
        &mut headers,
        "x-slack-signature",
        lossy_header(input.signature_header),
        input.duplicate_signature_header,
    );
    if let Some(timestamp_header) = input.timestamp_header {
        insert_header(
            &mut headers,
            "x-slack-request-timestamp",
            lossy_header(timestamp_header),
            input.duplicate_timestamp_header,
        );
    }
    let _ = SlackWebhook::new(SHARED_SECRET).verify_and_parse(&headers, &bounded_body(input.body));
}

fn structured_stripe_header(input: &ProviderHeaderFuzz<'_>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(timestamp_header) = input.timestamp_header {
        let ts = lossy_header(timestamp_header);
        if !ts.is_empty() {
            parts.push(format!("t={ts}"));
        }
    }
    for signature in input.stripe_signatures.iter().take(MAX_STRIPE_SIGS) {
        let sig = lossy_header(signature);
        if !sig.is_empty() {
            parts.push(format!("v1={sig}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

fn exercise_stripe_negative(input: &ProviderHeaderFuzz<'_>) {
    let body = bounded_body(input.body);

    let mut raw_headers = HashMap::new();
    insert_header(
        &mut raw_headers,
        "stripe-signature",
        lossy_header(input.signature_header),
        input.duplicate_signature_header,
    );
    let _ = StripeWebhook::new(SHARED_SECRET).verify_and_parse(&raw_headers, &body);

    if let Some(structured_header) = structured_stripe_header(input) {
        let mut structured_headers = HashMap::new();
        insert_header(
            &mut structured_headers,
            "stripe-signature",
            structured_header,
            input.duplicate_signature_header,
        );
        let _ = StripeWebhook::new(SHARED_SECRET).verify_and_parse(&structured_headers, &body);
    }
}

fn github_positive_body(input: &ProviderHeaderFuzz<'_>) -> Vec<u8> {
    format!(
        r#"{{"fuzz":"{}"}}"#,
        lossy_id(input.body, "github-payload")
    )
    .into_bytes()
}

fn stripe_positive_body(input: &ProviderHeaderFuzz<'_>) -> Vec<u8> {
    format!(
        r#"{{"id":"evt_{}","type":"invoice.payment_succeeded"}}"#,
        lossy_id(input.delivery_id, "stripe")
    )
    .into_bytes()
}

fn slack_positive_body(input: &ProviderHeaderFuzz<'_>) -> Vec<u8> {
    format!(
        r#"{{"type":"event_callback","event_id":"Ev{}","event":{{"type":"message"}}}}"#,
        lossy_id(input.delivery_id, "slack")
    )
    .into_bytes()
}

fn linear_positive_body(input: &ProviderHeaderFuzz<'_>) -> Vec<u8> {
    format!(
        r#"{{"webhookId":"lin_{}","type":"Issue"}}"#,
        lossy_id(input.delivery_id, "linear")
    )
    .into_bytes()
}

fn exercise_positive_paths(input: &ProviderHeaderFuzz<'_>) {
    let github_body = github_positive_body(input);
    let github_signature = HmacSha256Verifier::new(SHARED_SECRET).compute(&github_body);
    let mut github_headers = HashMap::new();
    insert_header(
        &mut github_headers,
        "x-hub-signature-256",
        format!("sha256={github_signature}"),
        false,
    );
    github_headers.insert(
        "x-github-event".to_string(),
        lossy_id(input.event_type, "push"),
    );
    github_headers.insert(
        "x-github-delivery".to_string(),
        lossy_id(input.delivery_id, "delivery"),
    );
    assert!(
        GitHubWebhook::new(SHARED_SECRET)
            .verify_and_parse(&github_headers, &github_body)
            .is_ok(),
        "freshly signed GitHub payload must verify"
    );

    let linear_body = linear_positive_body(input);
    let linear_signature = HmacSha256Verifier::new(SHARED_SECRET).compute(&linear_body);
    let mut linear_headers = HashMap::new();
    insert_header(
        &mut linear_headers,
        "linear-signature",
        linear_signature,
        false,
    );
    assert!(
        LinearWebhook::new(SHARED_SECRET)
            .verify_and_parse(&linear_headers, &linear_body)
            .is_ok(),
        "freshly signed Linear payload must verify"
    );

    let now = Utc::now().timestamp();

    let slack_body = slack_positive_body(input);
    let slack_base = format!("v0:{now}:{}", String::from_utf8_lossy(&slack_body));
    let slack_signature = HmacSha256Verifier::new(SHARED_SECRET).compute(slack_base.as_bytes());
    let mut slack_headers = HashMap::new();
    insert_header(
        &mut slack_headers,
        "x-slack-signature",
        format!("v0={slack_signature}"),
        false,
    );
    insert_header(
        &mut slack_headers,
        "x-slack-request-timestamp",
        now.to_string(),
        false,
    );
    assert!(
        SlackWebhook::new(SHARED_SECRET)
            .verify_and_parse(&slack_headers, &slack_body)
            .is_ok(),
        "freshly signed Slack payload must verify"
    );

    let stripe_body = stripe_positive_body(input);
    let stripe_verifier = HmacSha256Verifier::new(SHARED_SECRET);
    let stripe_signed_payload = format!("{now}.{}", String::from_utf8_lossy(&stripe_body));
    let valid_signature = stripe_verifier.compute(stripe_signed_payload.as_bytes());
    let mut stripe_header_parts = vec![format!("t={now}")];
    if let Some(extra) = input.stripe_signatures.first() {
        let extra_sig = lossy_header(extra);
        if !extra_sig.is_empty() {
            stripe_header_parts.push(format!("v1={extra_sig}"));
        }
    }
    stripe_header_parts.push(format!("v1={valid_signature}"));
    let mut stripe_headers = HashMap::new();
    insert_header(
        &mut stripe_headers,
        "stripe-signature",
        stripe_header_parts.join(","),
        false,
    );
    assert!(
        StripeWebhook::new(SHARED_SECRET)
            .verify_and_parse(&stripe_headers, &stripe_body)
            .is_ok(),
        "freshly signed Stripe payload must verify"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = ProviderHeaderFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    exercise_github_negative(&input);
    exercise_stripe_negative(&input);
    exercise_slack_negative(&input);
    exercise_linear_negative(&input);
    exercise_positive_paths(&input);
});
