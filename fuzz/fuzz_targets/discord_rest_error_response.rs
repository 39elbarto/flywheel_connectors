#![no_main]
//! Discord connector REST API error and rate-limit parser fuzz target.
//!
//! Exercises the parser boundary that turns untrusted Discord JSON/header
//! values into retry delays. The oracle keeps retry-after values finite and
//! bounded before the retry loop converts them into `Duration`.

use arbitrary::{Arbitrary, Unstructured};
use fcp_discord::{__fuzz, DiscordError};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_RETRY_AFTER_SECONDS: f64 = 3600.0;

#[derive(Arbitrary, Debug)]
struct DiscordRestErrorFuzz<'a> {
    mode: u8,
    status_variant: u8,
    header_mode: u8,
    body_mode: u8,
    raw_body: &'a [u8],
    raw_header: &'a [u8],
    message: &'a [u8],
    retry_after_secs: i64,
}

fn bounded(bytes: &[u8], max: usize) -> &[u8] {
    &bytes[..bytes.len().min(max)]
}

fn lossy_field(bytes: &[u8], fallback: &str) -> String {
    let value = String::from_utf8_lossy(bounded(bytes, MAX_FIELD_BYTES))
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_FIELD_BYTES)
        .collect::<String>();
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn status_code(raw: u8) -> u16 {
    match raw % 8 {
        0 => 400,
        1 => 401,
        2 => 403,
        3 => 404,
        4 => 429,
        5 => 500,
        6 => 503,
        _ => 599,
    }
}

fn retry_after_value(input: &DiscordRestErrorFuzz<'_>) -> Value {
    match input.body_mode % 6 {
        0 => json!(input.retry_after_secs),
        1 => json!(-input.retry_after_secs.saturating_abs()),
        2 => json!(i64::MAX),
        3 => json!(lossy_field(input.raw_body, "not-a-number")),
        4 => Value::Null,
        _ => json!([input.retry_after_secs]),
    }
}

fn structured_body(input: &DiscordRestErrorFuzz<'_>, status: u16) -> Vec<u8> {
    let body = json!({
        "code": status,
        "message": lossy_field(input.message, "Discord API error"),
        "retry_after": retry_after_value(input),
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn malformed_body(input: &DiscordRestErrorFuzz<'_>, status: u16) -> Vec<u8> {
    let body = json!({
        "code": lossy_field(input.raw_body, "bad-code"),
        "message": status,
        "retry_after": {
            "seconds": input.retry_after_secs
        }
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn header_value(input: &DiscordRestErrorFuzz<'_>) -> Option<String> {
    match input.header_mode % 6 {
        0 => None,
        1 => Some(input.retry_after_secs.to_string()),
        2 => Some((-input.retry_after_secs.saturating_abs()).to_string()),
        3 => Some(i64::MAX.to_string()),
        4 => Some("NaN".to_string()),
        _ => Some(lossy_field(input.raw_header, "not-a-number")),
    }
}

fn assert_sanitized_retry_after(retry_after: f64) {
    assert!(retry_after.is_finite());
    assert!((0.0..=MAX_RETRY_AFTER_SECONDS).contains(&retry_after));
    let error = DiscordError::RateLimited { retry_after };
    let _ = error.retry_after();
}

fn exercise(status: u16, header: Option<&str>, body: &[u8]) {
    let bounded_body = bounded(body, MAX_BODY_BYTES);

    let retry_after = __fuzz::parse_rest_retry_after_seconds(header, bounded_body);
    assert_sanitized_retry_after(retry_after);

    let error = __fuzz::parse_rest_api_error_response(status, bounded_body);
    let _ = error.to_string();
    let _ = format!("{error:?}");
    let _ = error.retry_after();

    if let DiscordError::Api {
        retry_after: Some(value),
        ..
    } = error
    {
        assert_sanitized_retry_after(value);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = DiscordRestErrorFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_body.len() > MAX_BODY_BYTES {
        return;
    }

    let status = status_code(input.status_variant);
    let header = header_value(&input);
    match input.mode % 3 {
        0 => exercise(status, header.as_deref(), input.raw_body),
        1 => exercise(status, header.as_deref(), &structured_body(&input, status)),
        _ => exercise(status, header.as_deref(), &malformed_body(&input, status)),
    }
});
