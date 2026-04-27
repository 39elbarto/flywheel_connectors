#![no_main]
//! Anthropic response and stream-event deserializer fuzz target.
//!
//! Exercises the untrusted JSON boundary for Messages API responses and SSE
//! event payloads without constructing an HTTP client.

use arbitrary::{Arbitrary, Unstructured};
use fcp_anthropic::types::{ApiError, MessagesResponse, StreamEvent};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_RAW_JSON_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_CONTENT_BLOCKS: usize = 16;

#[derive(Arbitrary, Debug)]
struct AnthropicResponseFuzz<'a> {
    mode: u8,
    raw_json: &'a [u8],
    id: &'a [u8],
    model: &'a [u8],
    text: &'a [u8],
    tool_name: &'a [u8],
    input_tokens: u32,
    output_tokens: u32,
    stop_selector: u8,
    event_selector: u8,
    content_blocks: Vec<ContentBlockFuzz<'a>>,
}

#[derive(Arbitrary, Debug)]
struct ContentBlockFuzz<'a> {
    block_selector: u8,
    id: &'a [u8],
    name: &'a [u8],
    text: &'a [u8],
}

fn bounded(bytes: &[u8], max: usize) -> &[u8] {
    &bytes[..bytes.len().min(max)]
}

fn lossy_field(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bounded(bytes, MAX_FIELD_BYTES))
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_FIELD_BYTES)
        .collect()
}

fn usage(input: &AnthropicResponseFuzz<'_>) -> Value {
    json!({
        "input_tokens": input.input_tokens,
        "output_tokens": input.output_tokens,
        "cache_creation_input_tokens": input.input_tokens / 2,
        "cache_read_input_tokens": input.input_tokens / 3,
    })
}

fn stop_reason(selector: u8) -> Option<&'static str> {
    match selector % 5 {
        0 => Some("end_turn"),
        1 => Some("max_tokens"),
        2 => Some("stop_sequence"),
        3 => Some("tool_use"),
        _ => None,
    }
}

fn response_content_block(block: &ContentBlockFuzz<'_>) -> Value {
    match block.block_selector % 3 {
        0 => json!({
            "type": "text",
            "text": lossy_field(block.text),
        }),
        1 => json!({
            "type": "tool_use",
            "id": lossy_field(block.id),
            "name": lossy_field(block.name),
            "input": {"value": lossy_field(block.text)},
        }),
        _ => json!({
            "type": "unknown",
            "text": lossy_field(block.text),
        }),
    }
}

fn response_content(input: &AnthropicResponseFuzz<'_>) -> Vec<Value> {
    input
        .content_blocks
        .iter()
        .take(MAX_CONTENT_BLOCKS)
        .map(response_content_block)
        .collect()
}

fn structured_message_response(input: &AnthropicResponseFuzz<'_>) -> Value {
    json!({
        "id": lossy_field(input.id),
        "type": "message",
        "role": "assistant",
        "content": response_content(input),
        "model": lossy_field(input.model),
        "stop_reason": stop_reason(input.stop_selector),
        "stop_sequence": if input.stop_selector % 2 == 0 {
            Some(lossy_field(input.text))
        } else {
            None
        },
        "usage": usage(input),
    })
}

fn structured_stream_event(input: &AnthropicResponseFuzz<'_>) -> Value {
    let error = json!({
        "type": lossy_field(input.tool_name),
        "message": lossy_field(input.text),
    });

    match input.event_selector % 8 {
        0 => json!({
            "type": "message_start",
            "message": {
                "id": lossy_field(input.id),
                "role": "assistant",
                "model": lossy_field(input.model),
                "usage": usage(input),
            },
        }),
        1 => json!({
            "type": "content_block_start",
            "index": input.output_tokens,
            "content_block": {
                "type": "text",
                "text": lossy_field(input.text),
            },
        }),
        2 => json!({
            "type": "content_block_delta",
            "index": input.output_tokens,
            "delta": {
                "type": "text_delta",
                "text": lossy_field(input.text),
            },
        }),
        3 => json!({
            "type": "content_block_stop",
            "index": input.output_tokens,
        }),
        4 => json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": stop_reason(input.stop_selector),
                "stop_sequence": lossy_field(input.text),
            },
            "usage": usage(input),
        }),
        5 => json!({ "type": "message_stop" }),
        6 => json!({ "type": "ping" }),
        _ => json!({
            "type": "error",
            "error": error,
        }),
    }
}

fn exercise_value(value: Value) {
    if let Ok(response) = serde_json::from_value::<MessagesResponse>(value.clone()) {
        let _ = response
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .count();
        let _ = response.usage.total_tokens();
    }

    if let Ok(event) = serde_json::from_value::<StreamEvent>(value.clone()) {
        match event {
            StreamEvent::MessageStart { message } => {
                let _ = message.usage.total_tokens();
            }
            StreamEvent::MessageDelta { usage, .. } => {
                let _ = usage.total_tokens();
            }
            StreamEvent::Error { error } => {
                let _ = (error.error_type, error.message);
            }
            _ => {}
        }
    }

    let _ = serde_json::from_value::<ApiError>(value);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = Unstructured::new(data).arbitrary::<AnthropicResponseFuzz<'_>>() {
        match input.mode % 3 {
            0 => {
                if let Ok(value) =
                    serde_json::from_slice::<Value>(bounded(input.raw_json, MAX_RAW_JSON_BYTES))
                {
                    exercise_value(value);
                }
            }
            1 => exercise_value(structured_message_response(&input)),
            _ => exercise_value(structured_stream_event(&input)),
        }
    } else if let Ok(value) = serde_json::from_slice::<Value>(bounded(data, MAX_RAW_JSON_BYTES)) {
        exercise_value(value);
    }
});
