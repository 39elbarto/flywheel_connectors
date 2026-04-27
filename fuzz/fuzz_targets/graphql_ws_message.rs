#![no_main]
//! GraphQL-WS message decoder fuzz target (`flywheel_connectors-ren6p`).
//!
//! Drives `fcp_graphql::subscription::decode_ws_message` through the crate's
//! hidden fuzz wrapper with adversarial WebSocket messages:
//! - raw text and binary frames, including malformed JSON and non-UTF-8 bytes,
//! - structured GraphQL-WS message variants with hostile ids and payloads,
//! - ping, pong, and close control frames that must return protocol errors.
//!
//! Invariant: decoding must never panic, and both success and error values must
//! remain printable so subscription diagnostics cannot panic on hostile input.

use arbitrary::{Arbitrary, Unstructured};
use fcp_graphql::__fuzz;
use fcp_streaming::{WsCloseFrame, WsMessage};
use libfuzzer_sys::fuzz_target;

const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CONTROL_BYTES: usize = 125;
const MAX_STRING_BYTES: usize = 8 * 1024;

#[derive(Arbitrary, Debug)]
struct FuzzInput<'a> {
    mode: u8,
    message_type_raw: u8,
    close_code: u16,
    frame: &'a [u8],
    id: &'a [u8],
    payload: &'a [u8],
}

fn bounded_bytes(bytes: &[u8], cap: usize) -> &[u8] {
    &bytes[..bytes.len().min(cap)]
}

fn bounded_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bounded_bytes(bytes, MAX_STRING_BYTES)).into_owned()
}

fn message_type(raw: u8) -> &'static str {
    match raw % 10 {
        0 => "connection_init",
        1 => "connection_ack",
        2 => "ping",
        3 => "pong",
        4 => "subscribe",
        5 => "next",
        6 => "error",
        7 => "complete",
        8 => "ka",
        _ => "unknown",
    }
}

fn exercise(message: WsMessage) {
    match __fuzz::decode_message(message) {
        Ok(decoded) => {
            let _ = decoded.message_type.len();
            let _ = decoded.id.as_deref().map(str::len);
            if let Some(payload) = decoded.payload {
                let _ = payload.to_string();
            }
        }
        Err(err) => {
            let _ = err.to_string();
            let _ = format!("{err:?}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.frame.len() > MAX_FRAME_BYTES || input.payload.len() > MAX_FRAME_BYTES {
        return;
    }

    match input.mode % 8 {
        0 => {
            if let Ok(text) = std::str::from_utf8(input.frame) {
                exercise(WsMessage::Text(text.to_owned()));
            }
        }
        1 => exercise(WsMessage::Binary(input.frame.to_vec().into())),
        2 => exercise(WsMessage::Ping(
            bounded_bytes(input.frame, MAX_CONTROL_BYTES)
                .to_vec()
                .into(),
        )),
        3 => exercise(WsMessage::Pong(
            bounded_bytes(input.frame, MAX_CONTROL_BYTES)
                .to_vec()
                .into(),
        )),
        4 => exercise(WsMessage::Close(None)),
        5 => exercise(WsMessage::Close(Some(WsCloseFrame::new(
            input.close_code,
            bounded_string(input.frame),
        )))),
        6 => {
            let json = serde_json::json!({
                "type": message_type(input.message_type_raw),
                "id": bounded_string(input.id),
                "payload": {
                    "data": bounded_string(input.payload),
                    "raw_len": input.payload.len(),
                }
            });
            let serialized = json.to_string();
            exercise(WsMessage::Text(serialized.clone()));
            exercise(WsMessage::Binary(serialized.into_bytes().into()));
        }
        _ => {
            let json = serde_json::json!({
                "type": message_type(input.message_type_raw),
                "payload": bounded_string(input.payload),
            });
            exercise(WsMessage::Text(json.to_string()));
        }
    }
});
