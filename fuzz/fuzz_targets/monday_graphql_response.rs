#![no_main]
//! Monday connector GraphQL response decoder fuzz target.
//!
//! Drives the response wrappers used by `MondayClient::handle_response` and
//! `MondayClient::handle_error`: successful GraphQL envelopes, GraphQL error
//! arrays, non-GraphQL API error bodies, and raw JSON bytes from the service.

use arbitrary::{Arbitrary, Unstructured};
use fcp_monday::types::{ApiErrorResponse, GraphQLResponse};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_RAW_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_ERRORS: usize = 16;

#[derive(Arbitrary, Debug)]
struct MondayGraphqlResponseFuzz<'a> {
    mode: u8,
    raw_json: &'a [u8],
    data_json: &'a [u8],
    error_messages: Vec<&'a [u8]>,
    error_message: Option<&'a [u8]>,
    error_code: Option<&'a [u8]>,
    include_data: bool,
    include_errors: bool,
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

fn data_value(input: &MondayGraphqlResponseFuzz<'_>) -> Value {
    serde_json::from_slice::<Value>(bounded(input.data_json, MAX_RAW_BYTES))
        .unwrap_or_else(|_| json!({ "boards": [{ "id": "1", "name": "Board" }] }))
}

fn graphql_response_value(input: &MondayGraphqlResponseFuzz<'_>) -> Value {
    let mut body = json!({});
    if input.include_data {
        body["data"] = data_value(input);
    }
    if input.include_errors {
        let errors = input
            .error_messages
            .iter()
            .take(MAX_ERRORS)
            .map(|message| json!({ "message": lossy_field(message, "GraphQL error") }))
            .collect::<Vec<_>>();
        body["errors"] = Value::Array(errors);
    }
    body
}

fn malformed_graphql_value(input: &MondayGraphqlResponseFuzz<'_>) -> Value {
    json!({
        "data": if input.include_data { data_value(input) } else { Value::Null },
        "errors": [
            { "message": input.mode },
            { "not_message": lossy_field(input.raw_json, "missing message field") },
        ],
    })
}

fn api_error_value(input: &MondayGraphqlResponseFuzz<'_>) -> Value {
    let mut body = json!({});
    if let Some(message) = input.error_message {
        body["error_message"] = json!(lossy_field(message, "API error"));
    }
    if let Some(code) = input.error_code {
        body["error_code"] = json!(lossy_field(code, "ColumnValueException"));
    }
    body
}

fn exercise_graphql_bytes(bytes: &[u8]) {
    if let Ok(response) = serde_json::from_slice::<GraphQLResponse>(bounded(bytes, MAX_RAW_BYTES)) {
        exercise_graphql_response(response);
    }
}

fn exercise_graphql_value(value: Value) {
    if let Ok(response) = serde_json::from_value::<GraphQLResponse>(value) {
        exercise_graphql_response(response);
    }
}

fn exercise_graphql_response(response: GraphQLResponse) {
    if let Some(errors) = response.errors {
        let joined = errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let _ = joined.len();
    }
    if let Some(data) = response.data {
        let _ = data.to_string();
    }
}

fn exercise_api_error_value(value: Value) {
    if let Ok(response) = serde_json::from_value::<ApiErrorResponse>(value) {
        let _ = response.error_message.as_deref().map(str::len);
        let _ = response.error_code.as_deref().map(str::len);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = MondayGraphqlResponseFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_json.len() > MAX_RAW_BYTES || input.data_json.len() > MAX_RAW_BYTES {
        return;
    }

    match input.mode % 4 {
        0 => exercise_graphql_bytes(input.raw_json),
        1 => exercise_graphql_value(graphql_response_value(&input)),
        2 => exercise_graphql_value(malformed_graphql_value(&input)),
        _ => exercise_api_error_value(api_error_value(&input)),
    }
});
