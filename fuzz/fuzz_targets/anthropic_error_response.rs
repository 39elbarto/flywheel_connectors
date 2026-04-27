#![no_main]
//! Anthropic error-response parser fuzz target.
//!
//! Exercises untrusted error JSON and `Retry-After` header values before they
//! become connector retry timing. The oracle keeps parsed delays bounded so
//! malformed service input cannot overflow or schedule unreasonable sleeps.

use arbitrary::{Arbitrary, Unstructured};
use fcp_anthropic::{__fuzz, error::AnthropicError};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_RETRY_AFTER_MS: u64 = 60 * 60 * 1000;

#[derive(Arbitrary, Debug)]
struct AnthropicErrorFuzz<'a> {
    mode: u8,
    status_variant: u8,
    header_mode: u8,
    raw_body: &'a [u8],
    raw_header: &'a [u8],
    error_type: &'a [u8],
    message: &'a [u8],
    retry_after_secs: u64,
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
        6 => 529,
        _ => 599,
    }
}

fn header_value(input: &AnthropicErrorFuzz<'_>) -> Option<String> {
    match input.header_mode % 6 {
        0 => None,
        1 => Some(input.retry_after_secs.to_string()),
        2 => Some(u64::MAX.to_string()),
        3 => Some("-1".to_string()),
        4 => Some("1.5".to_string()),
        _ => Some(lossy_field(input.raw_header, "not-a-number")),
    }
}

fn structured_error_body(input: &AnthropicErrorFuzz<'_>) -> Vec<u8> {
    let body = json!({
        "error": {
            "type": lossy_field(input.error_type, "rate_limit_error"),
            "message": lossy_field(input.message, "Anthropic API error"),
        }
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn malformed_error_body(input: &AnthropicErrorFuzz<'_>) -> Vec<u8> {
    let body = json!({
        "error": {
            "type": input.retry_after_secs,
            "message": ["bad", lossy_field(input.raw_body, "shape")],
        }
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn assert_bounded_delay(ms: u64) {
    assert!(ms <= MAX_RETRY_AFTER_MS);
}

fn exercise(status: u16, header: Option<&str>, body: &[u8]) {
    if let Some(header) = header {
        if let Some(delay) = __fuzz::parse_retry_after_header(header) {
            assert_bounded_delay(delay);
        }
    }

    let error = __fuzz::parse_error_response_bytes(status, bounded(body, MAX_BODY_BYTES), header);
    let _ = error.to_string();
    let _ = format!("{error:?}");
    let _ = error.retry_after();

    match error {
        AnthropicError::RateLimited { retry_after_ms }
        | AnthropicError::Overloaded { retry_after_ms } => {
            assert_bounded_delay(retry_after_ms);
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = AnthropicErrorFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_body.len() > MAX_BODY_BYTES {
        return;
    }

    let status = status_code(input.status_variant);
    let header = header_value(&input);
    match input.mode % 3 {
        0 => exercise(status, header.as_deref(), input.raw_body),
        1 => exercise(status, header.as_deref(), &structured_error_body(&input)),
        _ => exercise(status, header.as_deref(), &malformed_error_body(&input)),
    }
});
