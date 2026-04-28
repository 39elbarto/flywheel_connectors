#![no_main]

use fcp_webhook::{DeliveryStatus, EventMetadata, EventSubscription, WebhookEvent};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_SYNTHETIC_TEXT_CHARS: usize = 128;

fn json_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("webhook event type should serialize")
}

fn exercise_event(event: WebhookEvent) {
    let _ = format!("{event:?}");
    let _ = event.header("x-fcp-fuzz-header");
    let _ = event.get("repository.name");
    let _ = event.get_str("repository.name");
    let _ = event.get_i64("delivery.attempt");

    assert!(event.matches_type("*"));
    assert!(event.matches_type(&event.event_type));
    if let Some(prefix) = event.event_type.chars().next() {
        let wildcard = format!("{prefix}*");
        let _ = event.matches_type(&wildcard);
    }

    let all = EventSubscription::all();
    assert!(all.matches(&event));

    let exact = EventSubscription::for_types(vec![event.event_type.clone()]);
    assert!(exact.matches(&event));

    let provider = EventSubscription::all().with_provider(event.provider.clone());
    assert!(provider.matches(&event));

    let encoded = serde_json::to_vec(&event).expect("webhook event should serialize");
    let decoded: WebhookEvent =
        serde_json::from_slice(&encoded).expect("serialized webhook event should decode");
    assert_eq!(json_value(&decoded), json_value(&event));
}

fn exercise_metadata(metadata: EventMetadata) {
    let encoded = serde_json::to_vec(&metadata).expect("metadata should serialize");
    let decoded: EventMetadata =
        serde_json::from_slice(&encoded).expect("serialized metadata should decode");
    assert_eq!(json_value(&decoded), json_value(&metadata));
}

fn synthetic_event(raw: &str) -> WebhookEvent {
    let text = raw
        .chars()
        .take(MAX_SYNTHETIC_TEXT_CHARS)
        .collect::<String>();
    WebhookEvent::new(text.clone(), format!("fuzz.{text}"), "fcp-fuzz")
        .with_payload(Value::String(text))
        .with_default_webhook_taint()
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(event) = serde_json::from_slice::<WebhookEvent>(data) {
        exercise_event(event);
    }

    if let Ok(metadata) = serde_json::from_slice::<EventMetadata>(data) {
        exercise_metadata(metadata);
    }

    if let Ok(status) = serde_json::from_slice::<DeliveryStatus>(data) {
        let encoded = serde_json::to_vec(&status).expect("delivery status should serialize");
        let decoded: DeliveryStatus =
            serde_json::from_slice(&encoded).expect("serialized status should decode");
        assert_eq!(decoded, status);
    }

    if let Ok(raw) = std::str::from_utf8(data) {
        exercise_event(synthetic_event(raw));
    }
});
