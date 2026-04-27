#![no_main]
//! Discord Gateway payload parser fuzz target.
//!
//! Exercises untrusted WebSocket JSON frames before they reach the gateway
//! event loop, including the Hello heartbeat interval validation that protects
//! downstream timer arithmetic.

use arbitrary::{Arbitrary, Unstructured};
use fcp_discord::types::{
    GatewayHello, GatewayPayload, MAX_GATEWAY_HEARTBEAT_INTERVAL_MS, validate_gateway_hello,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_RAW_JSON_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;

#[derive(Arbitrary, Debug)]
struct DiscordGatewayFuzz<'a> {
    mode: u8,
    raw_json: &'a [u8],
    op_selector: u8,
    sequence: Option<u64>,
    event_name: Option<&'a [u8]>,
    heartbeat_interval: u64,
    data_kind: u8,
    data_text: Option<&'a [u8]>,
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

fn gateway_opcode(selector: u8) -> i32 {
    match selector % 8 {
        0 => 0,
        1 => 1,
        2 => 7,
        3 => 9,
        4 => 10,
        5 => 11,
        6 => -1,
        _ => 255,
    }
}

fn event_name(input: Option<&[u8]>) -> Option<String> {
    input.map(lossy_field).filter(|name| !name.is_empty())
}

fn data_value(input: &DiscordGatewayFuzz<'_>) -> Value {
    match input.data_kind % 6 {
        0 => Value::Null,
        1 => json!(lossy_field(input.data_text.unwrap_or_default())),
        2 => json!(input.heartbeat_interval),
        3 => json!({
            "heartbeat_interval": input.heartbeat_interval,
        }),
        4 => json!({
            "content": lossy_field(input.data_text.unwrap_or_default()),
        }),
        _ => json!([lossy_field(input.data_text.unwrap_or_default())]),
    }
}

fn structured_payload(input: &DiscordGatewayFuzz<'_>) -> Value {
    json!({
        "op": gateway_opcode(input.op_selector),
        "d": data_value(input),
        "s": input.sequence,
        "t": event_name(input.event_name),
    })
}

fn exercise_value(value: Value) {
    if let Ok(payload) = serde_json::from_value::<GatewayPayload>(value) {
        if payload.op == 10 {
            if let Ok(hello) = serde_json::from_value::<GatewayHello>(payload.d.unwrap_or_default())
            {
                match validate_gateway_hello(hello) {
                    Ok(valid) => {
                        assert!(valid.heartbeat_interval > 0);
                        assert!(valid.heartbeat_interval <= MAX_GATEWAY_HEARTBEAT_INTERVAL_MS);
                    }
                    Err(error) => {
                        let message = error.to_string();
                        assert!(message.contains("heartbeat_interval"));
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = Unstructured::new(data).arbitrary::<DiscordGatewayFuzz<'_>>() {
        match input.mode % 2 {
            0 => {
                if let Ok(value) =
                    serde_json::from_slice::<Value>(bounded(input.raw_json, MAX_RAW_JSON_BYTES))
                {
                    exercise_value(value);
                }
            }
            _ => exercise_value(structured_payload(&input)),
        }
    } else if let Ok(value) = serde_json::from_slice::<Value>(bounded(data, MAX_RAW_JSON_BYTES)) {
        exercise_value(value);
    }
});
