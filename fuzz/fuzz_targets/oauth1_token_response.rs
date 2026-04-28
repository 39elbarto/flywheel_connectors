#![no_main]

use std::fmt::Write as _;

use arbitrary::{Arbitrary, Unstructured};
use fcp_oauth::__fuzz;
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BODY_BYTES: usize = 16 * 1024;
const MAX_FIELD_BYTES: usize = 256;

#[derive(Arbitrary, Debug)]
struct OAuth1TokenResponseFuzz<'a> {
    mode: u8,
    raw_body: &'a [u8],
    token: &'a [u8],
    token_secret: &'a [u8],
    callback_confirmed: bool,
    user_id: Option<&'a [u8]>,
    screen_name: Option<&'a [u8]>,
}

fn bounded(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_FIELD_BYTES)]
}

fn form_component(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for &byte in bounded(bytes) {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

fn request_token_body(input: &OAuth1TokenResponseFuzz<'_>) -> String {
    format!(
        "oauth_token={}&oauth_token_secret={}&oauth_callback_confirmed={}",
        form_component(input.token),
        form_component(input.token_secret),
        input.callback_confirmed
    )
}

fn access_token_body(input: &OAuth1TokenResponseFuzz<'_>) -> String {
    let mut body = format!(
        "oauth_token={}&oauth_token_secret={}",
        form_component(input.token),
        form_component(input.token_secret)
    );
    if let Some(user_id) = input.user_id {
        body.push_str("&user_id=");
        body.push_str(&form_component(user_id));
    }
    if let Some(screen_name) = input.screen_name {
        body.push_str("&screen_name=");
        body.push_str(&form_component(screen_name));
    }
    body
}

fn exercise_request_token(body: &str) {
    if let Ok(token) = __fuzz::parse_request_token_body(body) {
        let _ = format!("{token:?}");
    }
}

fn exercise_access_token(body: &str) {
    if let Ok(tokens) = __fuzz::parse_access_token_body(body) {
        let _ = format!("{tokens:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = OAuth1TokenResponseFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_body.len() <= MAX_RAW_BODY_BYTES {
        let raw = String::from_utf8_lossy(input.raw_body);
        match input.mode % 3 {
            0 => exercise_request_token(&raw),
            1 => exercise_access_token(&raw),
            _ => {
                exercise_request_token(&raw);
                exercise_access_token(&raw);
            }
        }
    }

    exercise_request_token(&request_token_body(&input));
    exercise_access_token(&access_token_body(&input));
});
