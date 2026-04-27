#![no_main]
//! GitHub connector webhook payload parser fuzz target.
//!
//! Drives `fcp_github::types::WebhookPayload`, the typed envelope consumed by
//! `github.process_webhook` after the host has verified the HMAC header. The
//! harness mixes raw JSON bytes with structure-aware valid envelopes so enum
//! decoding, optional repository/sender fields, arbitrary event data, and topic
//! derivation all stay covered.

use arbitrary::{Arbitrary, Unstructured};
use fcp_github::types::{WebhookPayload, WebhookRepository, WebhookSender};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

const MAX_RAW_JSON_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_DATA_JSON_BYTES: usize = 8 * 1024;

#[derive(Arbitrary, Debug)]
struct GitHubWebhookPayloadFuzz<'a> {
    mode: u8,
    raw_json: &'a [u8],
    event_type: u8,
    action: Option<u8>,
    delivery_id: &'a [u8],
    data_json: &'a [u8],
    repo_id: u64,
    repo_full_name: &'a [u8],
    repo_url: &'a [u8],
    repo_private: bool,
    include_repository: bool,
    sender_login: &'a [u8],
    sender_id: u64,
    sender_avatar_url: Option<&'a [u8]>,
    include_sender: bool,
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

fn event_type(raw: u8) -> &'static str {
    match raw % 10 {
        0 => "issues",
        1 => "issue_comment",
        2 => "pull_request",
        3 => "pull_request_review",
        4 => "push",
        5 => "workflow_run",
        6 => "create",
        7 => "delete",
        8 => "release",
        _ => "ping",
    }
}

fn action(raw: u8) -> &'static str {
    match raw % 12 {
        0 => "opened",
        1 => "closed",
        2 => "reopened",
        3 => "edited",
        4 => "created",
        5 => "deleted",
        6 => "synchronize",
        7 => "submitted",
        8 => "completed",
        9 => "requested",
        10 => "published",
        _ => "merged",
    }
}

fn data_value(input: &GitHubWebhookPayloadFuzz<'_>) -> Value {
    if let Ok(value) =
        serde_json::from_slice::<Value>(bounded(input.data_json, MAX_DATA_JSON_BYTES))
    {
        value
    } else if let Some(action_raw) = input.action {
        json!({ "action": action(action_raw) })
    } else {
        json!({})
    }
}

fn structured_payload(input: &GitHubWebhookPayloadFuzz<'_>) -> Value {
    let mut payload = json!({
        "event_type": event_type(input.event_type),
        "delivery_id": lossy_field(input.delivery_id, "delivery"),
        "data": data_value(input),
    });

    if input.include_repository {
        payload["repository"] = json!({
            "id": input.repo_id,
            "full_name": lossy_field(input.repo_full_name, "owner/repo"),
            "html_url": lossy_field(input.repo_url, "https://github.com/owner/repo"),
            "private": input.repo_private,
        });
    }

    if input.include_sender {
        let mut sender = json!({
            "login": lossy_field(input.sender_login, "octocat"),
            "id": input.sender_id,
        });
        if let Some(avatar_url) = input.sender_avatar_url {
            sender["avatar_url"] = json!(lossy_field(
                avatar_url,
                "https://avatars.githubusercontent.com/u/1",
            ));
        }
        payload["sender"] = sender;
    }

    payload
}

fn malformed_payload(input: &GitHubWebhookPayloadFuzz<'_>) -> Value {
    json!({
        "event_type": lossy_field(input.raw_json, "unknown_event"),
        "delivery_id": [lossy_field(input.delivery_id, "delivery")],
        "data": data_value(input),
        "repository": {
            "id": lossy_field(input.repo_full_name, "not-a-number"),
            "full_name": input.repo_id,
            "html_url": input.repo_private,
        },
        "sender": {
            "login": input.sender_id,
            "id": lossy_field(input.sender_login, "not-a-number"),
        }
    })
}

fn exercise_bytes(bytes: &[u8]) {
    if let Ok(payload) = serde_json::from_slice::<WebhookPayload>(bytes) {
        exercise_payload(payload);
    }
}

fn exercise_value(value: Value) {
    if let Ok(payload) = serde_json::from_value::<WebhookPayload>(value) {
        exercise_payload(payload);
    }
}

fn exercise_payload(payload: WebhookPayload) {
    let action = payload.data.get("action").and_then(Value::as_str);
    let topic = payload.event_type.to_topic(action);
    assert!(topic.starts_with("github."));

    let _ = payload.delivery_id.len();
    let _ = payload.repository.as_ref().map(repository_shape);
    let _ = payload.sender.as_ref().map(sender_shape);

    if let Ok(encoded) = serde_json::to_vec(&payload) {
        let _ = serde_json::from_slice::<WebhookPayload>(&encoded);
    }
}

fn repository_shape(repository: &WebhookRepository) -> usize {
    repository.full_name.len() + repository.html_url.len() + usize::from(repository.private)
}

fn sender_shape(sender: &WebhookSender) -> usize {
    sender.login.len() + sender.avatar_url.as_deref().map(str::len).unwrap_or(0)
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = GitHubWebhookPayloadFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw_json.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    match input.mode % 3 {
        0 => exercise_bytes(input.raw_json),
        1 => exercise_value(structured_payload(&input)),
        _ => exercise_value(malformed_payload(&input)),
    }
});
