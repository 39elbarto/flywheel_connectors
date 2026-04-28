#![no_main]
//! QQ access-token response parser fuzz target.
//!
//! Exercises serde parsing for the connector's token response shape and checks
//! that accepted responses keep token material redacted in `Debug` output.

use arbitrary::{Arbitrary, Unstructured};
use fcp_qq::types::AccessTokenResponse;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Number, Value};

const MAX_JSON_BYTES: usize = 4096;
const MAX_TOKEN_BYTES: usize = 512;

#[derive(Arbitrary, Debug)]
struct TokenResponseInput<'a> {
    raw_json: &'a [u8],
    token: &'a [u8],
    expires_in: u64,
    include_token: bool,
    include_expires_in: bool,
    malformed_expires_in: bool,
    extra_key: &'a [u8],
    extra_value: &'a [u8],
}

fn bounded_lossy(bytes: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).into_owned()
}

fn structured_value(input: &TokenResponseInput<'_>) -> Value {
    let mut object = Map::new();

    if input.include_token {
        object.insert(
            "access_token".to_string(),
            Value::String(bounded_lossy(input.token, MAX_TOKEN_BYTES)),
        );
    }

    if input.include_expires_in {
        let value = if input.malformed_expires_in {
            Value::String(input.expires_in.to_string())
        } else {
            Value::Number(Number::from(input.expires_in))
        };
        object.insert("expires_in".to_string(), value);
    }

    let extra_key = bounded_lossy(input.extra_key, 64);
    if !extra_key.is_empty() && extra_key != "access_token" && extra_key != "expires_in" {
        object.insert(
            extra_key,
            Value::String(bounded_lossy(input.extra_value, 256)),
        );
    }

    Value::Object(object)
}

fn assert_redacted_debug(response: &AccessTokenResponse) {
    let debug = format!("{response:?}");
    assert!(debug.contains("[REDACTED]"));
    if !response.access_token.is_empty() {
        assert!(!debug.contains(&response.access_token));
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = TokenResponseInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_json.len() <= MAX_JSON_BYTES {
        if let Ok(response) = serde_json::from_slice::<AccessTokenResponse>(input.raw_json) {
            assert_redacted_debug(&response);
        }
    }

    let structured = structured_value(&input);
    if let Ok(response) = serde_json::from_value::<AccessTokenResponse>(structured) {
        assert_redacted_debug(&response);
    }
});
