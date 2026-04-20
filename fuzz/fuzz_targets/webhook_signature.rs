#![no_main]
//! Fuzz harness for fcp-webhook signature verification.
//!
//! Walks fuzzer-chosen bytes through three orthogonal attack surfaces that
//! every real-world webhook receiver has to defend:
//!
//! 1. **Stripe `Stripe-Signature` header parser** — a tiny comma-separated
//!    key/value grammar that funnels straight into an HMAC verifier. A
//!    crash or infinite loop here is a DoS primitive any unauthenticated
//!    client can trigger before we even reach the HMAC.
//! 2. **Stripe end-to-end verify_and_parse** — the full `verify_and_parse`
//!    path with arbitrary headers and body, exercising header parsing,
//!    timestamp handling, HMAC verification, JSON parsing, and event
//!    construction.
//! 3. **GitHub verify_and_parse** — the same end-to-end path with the
//!    `sha256=` prefix parsing, case-insensitive header lookup, and
//!    hex-decoded HMAC-SHA256 verification.
//!
//! We also assert a lightweight positive invariant: a freshly minted
//! signature from `HmacSha256Verifier::compute` must verify against the
//! same key/body, and must fail to verify if a single byte of either
//! key or body is mutated. That gives the fuzzer coverage of the success
//! path in addition to the rejection path.

use std::collections::HashMap;

use fcp_webhook::{GitHubWebhook, HmacSha256Verifier, SignatureVerifier, StripeWebhook};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct WebhookSignatureSeed {
    header: String,
    event_type: String,
    body: String,
    secret: String,
    stripe_timestamp: Option<String>,
    stripe_signatures: Vec<String>,
}

fn split_first<'a>(bytes: &'a [u8], sep: u8) -> Option<(&'a [u8], &'a [u8])> {
    let pos = bytes.iter().position(|b| *b == sep)?;
    Some((&bytes[..pos], &bytes[pos + 1..]))
}

fn bytes_as_utf8(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

fn fuzz_stripe(signature_header: &str, body: &[u8]) {
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert("stripe-signature".to_string(), signature_header.to_string());

    // Fixed secret is fine — we are fuzzing the parser/verifier path,
    // not searching for key-recovery attacks.
    let stripe = StripeWebhook::new(b"fuzz-stripe-secret");
    let _ = stripe.verify_and_parse(&headers, body);
}

fn fuzz_github(signature_header: &str, event_type: &str, body: &[u8]) {
    let mut headers: HashMap<String, String> = HashMap::new();
    headers.insert(
        "x-hub-signature-256".to_string(),
        signature_header.to_string(),
    );
    headers.insert("x-github-event".to_string(), event_type.to_string());
    headers.insert("x-github-delivery".to_string(), "fuzz-delivery".to_string());

    let github = GitHubWebhook::new(b"fuzz-github-secret");
    let _ = github.verify_and_parse(&headers, body);
}

fn structured_stripe_header(seed: &WebhookSignatureSeed) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(ts) = seed.stripe_timestamp.as_deref().filter(|ts| !ts.is_empty()) {
        parts.push(format!("t={ts}"));
    }
    for signature in seed.stripe_signatures.iter().filter(|sig| !sig.is_empty()) {
        parts.push(format!("v1={signature}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

fn positive_hmac_round_trip(secret: &[u8], body: &[u8]) {
    let verifier = HmacSha256Verifier::new(secret);
    let signature = verifier.compute(body);

    // A freshly computed signature must validate.
    verifier
        .verify(body, &signature)
        .expect("self-signed payload must verify");

    // And so must the `sha256=` prefixed form that GitHub sends.
    let prefixed = format!("sha256={signature}");
    verifier
        .verify(body, &prefixed)
        .expect("prefixed self-signed payload must verify");

    // Mutating a single byte of the body must break verification — a
    // cheap differential that catches length-extension-style bugs.
    if !body.is_empty() {
        let mut tampered = body.to_vec();
        tampered[0] ^= 0x01;
        assert!(
            verifier.verify(&tampered, &signature).is_err(),
            "tampered payload must fail verification"
        );
    }

    // Same check for the key: a different secret must reject the signature.
    let other = HmacSha256Verifier::new([secret, b"-mutated"].concat());
    assert!(
        other.verify(body, &signature).is_err(),
        "mismatched key must fail verification"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(seed) = serde_json::from_slice::<WebhookSignatureSeed>(data) {
        let event_type = if seed.event_type.is_empty() {
            "push"
        } else {
            seed.event_type.as_str()
        };
        let secret = if seed.secret.is_empty() {
            b"fuzz-shared-secret".as_slice()
        } else {
            seed.secret.as_bytes()
        };
        fuzz_stripe(&seed.header, seed.body.as_bytes());
        if let Some(header) = structured_stripe_header(&seed) {
            fuzz_stripe(&header, seed.body.as_bytes());
        }
        fuzz_github(&seed.header, event_type, seed.body.as_bytes());
        positive_hmac_round_trip(secret, seed.body.as_bytes());
        return;
    }

    // Layout: [header_bytes] 0x1F [body_bytes]. 0x1F (unit separator) is
    // vanishingly rare in webhook headers and bodies, so the split is
    // usually clean; if it is missing we treat the whole input as header.
    let (header_raw, body) = split_first(data, 0x1F).unwrap_or((data, &[][..]));

    if header_raw.len() > MAX_HEADER_BYTES {
        return;
    }

    // Stripe signature header — whatever the fuzzer gives us, valid
    // UTF-8 or not. `parse_stripe_signature` operates on &str, so
    // invalid UTF-8 short-circuits out as a missing/invalid header
    // which is still a useful rejection path.
    if let Some(header_str) = bytes_as_utf8(header_raw) {
        fuzz_stripe(header_str, body);

        // GitHub wants a hex-string signature; reuse the same bytes.
        fuzz_github(header_str, "push", body);
    }

    // Positive-signature round-trip is independent of the Stripe/GitHub
    // header parsing above: treat the header portion as a secret and
    // the body portion as the payload to sign.
    positive_hmac_round_trip(header_raw, body);
});
