#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_slack::types::{
    AuthTestData, ChannelListData, HistoryData, PostMessageData, SearchData, SlackApiResponse,
    SocketModeOpenData, UserInfoData,
};
use libfuzzer_sys::fuzz_target;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 256;
const MAX_ITEMS: usize = 8;

#[derive(Arbitrary, Debug)]
struct SlackResponseInput<'a> {
    mode: u8,
    ok: bool,
    has_data: bool,
    raw_body: &'a [u8],
    channel: &'a [u8],
    ts: &'a [u8],
    text: &'a [u8],
    user: &'a [u8],
    team: &'a [u8],
    url: &'a [u8],
    error: &'a [u8],
    count: u8,
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

fn message(input: &SlackResponseInput<'_>, index: usize) -> Value {
    json!({
        "type": "message",
        "user": lossy_field(input.user, "U123"),
        "text": format!("{}-{index}", lossy_field(input.text, "hello")),
        "ts": format!("{}.{}", lossy_field(input.ts, "1700000000"), index),
        "thread_ts": Value::Null,
        "reply_count": index as u32,
        "reactions": [{
            "name": "thumbsup",
            "count": index as u32,
            "users": ["U1", "U2"]
        }],
        "files": [{
            "id": format!("F{index}"),
            "name": "fuzz.txt",
            "size": index as u64
        }]
    })
}

fn data_count(input: &SlackResponseInput<'_>) -> usize {
    usize::from(input.count).min(MAX_ITEMS)
}

fn error_value(input: &SlackResponseInput<'_>) -> Value {
    if input.ok {
        Value::Null
    } else {
        json!(lossy_field(input.error, "invalid_auth"))
    }
}

fn envelope(input: &SlackResponseInput<'_>, data: Value) -> Value {
    let mut envelope = json!({
        "ok": input.ok,
        "error": error_value(input),
    });
    if input.has_data {
        if let (Some(object), Some(data_object)) = (envelope.as_object_mut(), data.as_object()) {
            for (key, value) in data_object {
                object.insert(key.clone(), value.clone());
            }
        }
    }
    envelope
}

fn structured_body(input: &SlackResponseInput<'_>) -> Vec<u8> {
    let count = data_count(input);
    let data = match input.mode % 7 {
        0 => json!({
            "messages": (0..count).map(|index| message(input, index)).collect::<Vec<_>>(),
            "has_more": input.count % 2 == 0,
            "response_metadata": {"next_cursor": lossy_field(input.ts, "cursor")}
        }),
        1 => json!({
            "channel": lossy_field(input.channel, "C123"),
            "ts": lossy_field(input.ts, "1700000000.000001"),
            "message": message(input, 0)
        }),
        2 => json!({
            "channels": (0..count)
                .map(|index| json!({
                    "id": format!("C{index}"),
                    "name": format!("channel-{index}"),
                    "is_channel": true,
                    "num_members": index as u32,
                    "topic": {"value": "topic", "creator": "U1", "last_set": index as u64}
                }))
                .collect::<Vec<_>>(),
            "response_metadata": {"next_cursor": lossy_field(input.ts, "cursor")}
        }),
        3 => json!({
            "messages": {
                "total": count as u32,
                "matches": (0..count).map(|index| message(input, index)).collect::<Vec<_>>()
            }
        }),
        4 => json!({
            "url": lossy_field(input.url, "https://team.slack.com/"),
            "team": lossy_field(input.team, "Test Team"),
            "user": lossy_field(input.user, "testbot"),
            "team_id": "T123",
            "user_id": "U123",
            "bot_id": "B123",
            "is_enterprise_install": false
        }),
        5 => json!({
            "url": lossy_field(input.url, "wss://example.slack.com/socket")
        }),
        _ => json!({
            "user": {
                "id": lossy_field(input.user, "U123"),
                "name": "fuzzer",
                "profile": {
                    "display_name": "Fuzzer",
                    "email": "fuzzer@example.com"
                }
            }
        }),
    };
    serde_json::to_vec(&envelope(input, data)).unwrap_or_default()
}

fn body(input: &SlackResponseInput<'_>) -> Vec<u8> {
    match input.mode % 11 {
        7 => bounded(input.raw_body, MAX_BODY_BYTES).to_vec(),
        8 => b"{\"ok\":false,\"error\":\"channel_not_found\"}".to_vec(),
        9 => b"{\"ok\":true}".to_vec(),
        _ => structured_body(input),
    }
}

fn parse_all(bytes: &[u8]) {
    parse_one::<HistoryData>(bytes);
    parse_one::<PostMessageData>(bytes);
    parse_one::<ChannelListData>(bytes);
    parse_one::<SearchData>(bytes);
    parse_one::<AuthTestData>(bytes);
    parse_one::<SocketModeOpenData>(bytes);
    parse_one::<UserInfoData>(bytes);
}

fn parse_one<T>(bytes: &[u8])
where
    T: DeserializeOwned,
{
    let first = serde_json::from_slice::<SlackApiResponse<T>>(bytes);
    let second = serde_json::from_slice::<SlackApiResponse<T>>(bytes);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "Slack API response parser must be deterministic"
    );

    if let Ok(response) = first {
        let _ = response.ok;
        let _ = response.error.as_deref();
        let _ = response.data.is_some();
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = SlackResponseInput::arbitrary(&mut unstructured) else {
        return;
    };

    let bytes = body(&input);
    parse_all(&bytes);
});
