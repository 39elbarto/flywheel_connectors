#![no_main]
//! DingTalk connector callback-event parser fuzz target.
//!
//! Drives `normalize_callback_event`, the untrusted JSON boundary behind
//! `dingtalk.events.normalize`. The harness mixes raw JSON with structured
//! callback shapes so serde field-shape rejection and accepted-event invariants
//! both stay covered.

use arbitrary::{Arbitrary, Unstructured};
use fcp_dingtalk::client::normalize_callback_event;
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_RAW_JSON_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_AT_USERS: usize = 16;

#[derive(Arbitrary, Debug)]
struct DingtalkCallbackFuzz<'a> {
    mode: u8,
    raw_json: &'a [u8],
    msg_type: u8,
    text_content: Option<&'a [u8]>,
    sender_id: Option<&'a [u8]>,
    sender_nick: Option<&'a [u8]>,
    conversation_id: Option<&'a [u8]>,
    conversation_type: u8,
    conversation_title: Option<&'a [u8]>,
    chatbot_user_id: Option<&'a [u8]>,
    create_at: Option<i64>,
    msg_id: Option<&'a [u8]>,
    at_users: Vec<AtUserFuzz<'a>>,
    malformed_selector: u8,
}

#[derive(Arbitrary, Debug)]
struct AtUserFuzz<'a> {
    dingtalk_id: Option<&'a [u8]>,
    staff_id: Option<&'a [u8]>,
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

fn optional_field(value: Option<&[u8]>) -> Value {
    value.map_or(Value::Null, |bytes| json!(lossy_field(bytes)))
}

fn msg_type(raw: u8) -> &'static str {
    match raw % 5 {
        0 => "text",
        1 => "picture",
        2 => "richText",
        3 => "audio",
        _ => "unknown",
    }
}

fn conversation_type(raw: u8) -> &'static str {
    match raw % 4 {
        0 => "1",
        1 => "2",
        2 => " 2 ",
        _ => "99",
    }
}

fn at_users(input: &DingtalkCallbackFuzz<'_>) -> Value {
    Value::Array(
        input
            .at_users
            .iter()
            .take(MAX_AT_USERS)
            .map(|user| {
                json!({
                    "dingtalkId": optional_field(user.dingtalk_id),
                    "staffId": optional_field(user.staff_id),
                })
            })
            .collect(),
    )
}

fn structured_callback(input: &DingtalkCallbackFuzz<'_>) -> Value {
    let mut payload = json!({
        "msgType": msg_type(input.msg_type),
        "senderId": optional_field(input.sender_id),
        "senderNick": optional_field(input.sender_nick),
        "conversationId": optional_field(input.conversation_id),
        "conversationType": conversation_type(input.conversation_type),
        "conversationTitle": optional_field(input.conversation_title),
        "chatbotUserId": optional_field(input.chatbot_user_id),
        "createAt": input.create_at,
        "msgId": optional_field(input.msg_id),
        "atUsers": at_users(input),
    });

    if let Some(content) = input.text_content {
        payload["text"] = json!({ "content": lossy_field(content) });
    }

    payload
}

fn malformed_callback(input: &DingtalkCallbackFuzz<'_>) -> Value {
    match input.malformed_selector % 5 {
        0 => json!("not an event"),
        1 => json!({ "text": "plain string is not a text object" }),
        2 => json!({ "atUsers": "not an array" }),
        3 => json!({ "createAt": "not an integer timestamp" }),
        _ => json!({ "text": { "content": ["not", "a", "string"] } }),
    }
}

fn exercise_value(value: Value) {
    if let Ok(normalized) = normalize_callback_event(&value) {
        assert_eq!(normalized.event_type, "message");
        assert!(matches!(
            normalized.conversation_type.as_str(),
            "private" | "group" | "unknown"
        ));

        if normalized.at_bot {
            let bot_id = value
                .get("chatbotUserId")
                .and_then(Value::as_str)
                .map(str::trim);
            assert!(bot_id.is_some_and(|id| !id.is_empty()));
            let mentioned = value
                .get("atUsers")
                .and_then(Value::as_array)
                .is_some_and(|users| {
                    users.iter().any(|user| {
                        user.get("dingtalkId")
                            .and_then(Value::as_str)
                            .is_some_and(|id| Some(id.trim()) == bot_id)
                    })
                });
            assert!(mentioned);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(u) = Unstructured::new(data).arbitrary::<DingtalkCallbackFuzz<'_>>() {
        match u.mode % 3 {
            0 => {
                if let Ok(value) =
                    serde_json::from_slice::<Value>(bounded(u.raw_json, MAX_RAW_JSON_BYTES))
                {
                    exercise_value(value);
                }
            }
            1 => exercise_value(structured_callback(&u)),
            _ => exercise_value(malformed_callback(&u)),
        }
    } else if let Ok(value) = serde_json::from_slice::<Value>(bounded(data, MAX_RAW_JSON_BYTES)) {
        exercise_value(value);
    }
});
