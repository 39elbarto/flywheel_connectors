#![no_main]
//! Fuzz target for the HTTP rate-limit header parser
//! (`fcp-ratelimit::headers`).
//!
//! Bead flywheel_connectors-8714g. Drives `RateLimitHeaders::parse` and the
//! per-provider variants (GitHub / Twitter / Stripe / OpenAI / Anthropic) plus
//! `Provider::parse_headers` on adversarial header maps that exercise:
//!
//! - oversized integer values for `X-RateLimit-{Limit,Remaining,Reset}`,
//!   including u32::MAX boundaries and negative-looking inputs;
//! - `Retry-After` that is purely numeric, RFC-2822 HTTP-date, garbage,
//!   negative, or extreme (post-9999 dates);
//! - duplicate header keys at different ASCII cases (the lookup is case-
//!   insensitive — fuzzer must not surface a panic from the iter scan);
//! - whitespace, embedded NUL, very long values, non-UTF-8 has already been
//!   filtered by the HashMap<String, String> shape but extreme byte
//!   sequences remain;
//! - random selection of provider so cross-shape interactions are exercised.
//!
//! Invariants asserted across every input:
//! 1. The parser never panics.
//! 2. `is_limited()` is always callable on the result without panic.
//! 3. The parsed struct is `Clone`/`Debug`-safe (touch both).

use std::collections::HashMap;

use arbitrary::{Arbitrary, Unstructured};
use fcp_ratelimit::{Provider, RateLimitHeaders};
use libfuzzer_sys::fuzz_target;

const MAX_HEADER_COUNT: usize = 32;
const MAX_NAME_LEN: usize = 64;
const MAX_VALUE_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct FuzzInput<'a> {
    /// Selector mod 7 picks parser shape: parse, parse_github, parse_twitter,
    /// parse_stripe, parse_openai, parse_anthropic, Provider::parse_headers.
    mode: u8,
    /// Provider variant to drive when mode==6. Kept as raw u8 so the fuzzer
    /// can also feed bogus enum values; the From-style mapping below tolerates
    /// any byte.
    provider_raw: u8,
    /// Header (name, value) pairs, drawn directly from fuzz bytes. We
    /// dedupe the map by lowercased key but keep the original case so the
    /// case-insensitive lookup at headers.rs:249 is exercised.
    pairs: Vec<(&'a [u8], &'a [u8])>,
}

fn pick_provider(byte: u8) -> Provider {
    match byte % 6 {
        0 => Provider::Standard,
        1 => Provider::GitHub,
        2 => Provider::Twitter,
        3 => Provider::Stripe,
        4 => Provider::OpenAI,
        _ => Provider::Anthropic,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    let mut headers: HashMap<String, String> = HashMap::new();
    for (raw_name, raw_value) in input.pairs.iter().take(MAX_HEADER_COUNT) {
        let name_bytes = &raw_name[..raw_name.len().min(MAX_NAME_LEN)];
        let value_bytes = &raw_value[..raw_value.len().min(MAX_VALUE_LEN)];
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let value = String::from_utf8_lossy(value_bytes).into_owned();
        // HashMap will collapse duplicates by exact-string key, but the
        // parser walks the iterator with eq_ignore_ascii_case so different
        // case-mappings of the same logical header still surface.
        headers.insert(name, value);
    }

    let parsed = match input.mode % 7 {
        0 => RateLimitHeaders::parse(&headers),
        1 => RateLimitHeaders::parse_github(&headers),
        2 => RateLimitHeaders::parse_twitter(&headers),
        3 => RateLimitHeaders::parse_stripe(&headers),
        4 => RateLimitHeaders::parse_openai(&headers),
        5 => RateLimitHeaders::parse_anthropic(&headers),
        _ => pick_provider(input.provider_raw).parse_headers(&headers),
    };

    // Invariant: post-parse accessors never panic on adversarial input.
    let _ = parsed.is_limited();
    let _ = format!("{parsed:?}");
    let cloned = parsed.clone();
    let _ = cloned.is_limited();

    // Invariant: numeric bounds — limit/remaining/reset_seconds, when Some,
    // are within their declared u32/u64 ranges (compiler-enforced, but we
    // touch them to surface any future shape change).
    if let Some(limit) = parsed.limit {
        let _ = u64::from(limit);
    }
    if let Some(remaining) = parsed.remaining {
        let _ = u64::from(remaining);
    }
    if let Some(reset) = parsed.reset_seconds {
        let _ = reset;
    }
    if let Some(retry) = parsed.retry_after {
        // Retry-After must serialize back to a finite Duration. The std
        // Debug impl exercises Display under the hood.
        let _ = format!("{retry:?}");
    }
});
