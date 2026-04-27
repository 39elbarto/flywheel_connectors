#![no_main]
//! GitHub connector REST API error response parser fuzz target.
//!
//! Drives the private parser used for non-success GitHub REST responses through
//! a doc-hidden fuzz wrapper. The harness combines raw service bytes with
//! structured GitHub error envelopes across status codes that map to retry,
//! auth, not-found, validation, merge-conflict, and generic API errors.

use arbitrary::{Arbitrary, Unstructured};
use fcp_github::{client::__fuzz, error::GitHubError};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_VALIDATION_ERRORS: usize = 16;

#[derive(Arbitrary, Debug)]
struct GitHubApiErrorFuzz<'a> {
    mode: u8,
    status_variant: u8,
    raw_body: &'a [u8],
    message: &'a [u8],
    documentation_url: Option<&'a [u8]>,
    validation_errors: Vec<ValidationErrorFuzz<'a>>,
    retry_after_secs: Option<u64>,
}

#[derive(Arbitrary, Debug)]
struct ValidationErrorFuzz<'a> {
    resource: Option<&'a [u8]>,
    field: Option<&'a [u8]>,
    code: Option<&'a [u8]>,
    message: Option<&'a [u8]>,
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
    match raw % 10 {
        0 => 400,
        1 => 401,
        2 => 403,
        3 => 404,
        4 => 409,
        5 => 422,
        6 => 429,
        7 => 500,
        8 => 503,
        _ => 599,
    }
}

fn optional_field(value: Option<&[u8]>, fallback: &str) -> Option<Value> {
    value.map(|bytes| json!(lossy_field(bytes, fallback)))
}

fn structured_error_body(input: &GitHubApiErrorFuzz<'_>) -> Vec<u8> {
    let mut body = json!({
        "message": lossy_field(input.message, "GitHub API error"),
    });

    if let Some(documentation_url) =
        optional_field(input.documentation_url, "https://docs.github.com/rest")
    {
        body["documentation_url"] = documentation_url;
    }

    let errors = input
        .validation_errors
        .iter()
        .take(MAX_VALIDATION_ERRORS)
        .map(|error| {
            let mut value = json!({});
            if let Some(resource) = optional_field(error.resource, "Issue") {
                value["resource"] = resource;
            }
            if let Some(field) = optional_field(error.field, "title") {
                value["field"] = field;
            }
            if let Some(code) = optional_field(error.code, "missing_field") {
                value["code"] = code;
            }
            if let Some(message) = optional_field(error.message, "validation failed") {
                value["message"] = message;
            }
            value
        })
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        body["errors"] = Value::Array(errors);
    }

    serde_json::to_vec(&body).unwrap_or_default()
}

fn malformed_error_body(input: &GitHubApiErrorFuzz<'_>) -> Vec<u8> {
    let body = json!({
        "message": input.status_variant,
        "documentation_url": input.mode,
        "errors": [
            { "resource": input.status_variant, "field": true, "code": ["bad"] },
            lossy_field(input.raw_body, "not-an-object"),
        ]
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn exercise(status: u16, body: &[u8], retry_after_secs: Option<u64>) {
    let error = __fuzz::parse_api_error_response(
        status,
        bounded(body, MAX_BODY_BYTES),
        retry_after_secs.map(|secs| secs.min(86_400)),
    );
    let _ = error.to_string();
    let _ = format!("{error:?}");

    if status == 429 {
        assert!(matches!(error, GitHubError::RateLimited { .. }));
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = GitHubApiErrorFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_body.len() > MAX_BODY_BYTES {
        return;
    }

    let status = status_code(input.status_variant);
    match input.mode % 3 {
        0 => exercise(status, input.raw_body, input.retry_after_secs),
        1 => exercise(
            status,
            &structured_error_body(&input),
            input.retry_after_secs,
        ),
        _ => exercise(
            status,
            &malformed_error_body(&input),
            input.retry_after_secs,
        ),
    }
});
