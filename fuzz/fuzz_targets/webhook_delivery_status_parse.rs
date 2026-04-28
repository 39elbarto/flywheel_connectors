#![no_main]

//! Fuzz target for webhook delivery-status JSON parsing.
//!
//! Provider/header fuzzing covers signature grammars. This target drives the
//! smaller serde parser boundary that turns untrusted JSON into
//! `DeliveryStatus` and the defaulted `EventMetadata.status` field.

use arbitrary::{Arbitrary, Unstructured};
use fcp_webhook::{DeliveryStatus, EventMetadata};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const MAX_JSON_BYTES: usize = 4 * 1024;

#[derive(Arbitrary, Debug)]
struct Input {
    raw_json: Vec<u8>,
    status_choice: u8,
}

fn bounded_json(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_JSON_BYTES)]
}

fn assert_status_roundtrip(status: DeliveryStatus, expected_name: &str) {
    let encoded = serde_json::to_string(&status).expect("DeliveryStatus must serialize");
    assert_eq!(encoded, format!("\"{expected_name}\""));

    let decoded: DeliveryStatus =
        serde_json::from_str(&encoded).expect("serialized DeliveryStatus must parse");
    assert_eq!(decoded, status);
}

fn generated_status(choice: u8) -> (DeliveryStatus, &'static str) {
    match choice % 4 {
        0 => (DeliveryStatus::Pending, "pending"),
        1 => (DeliveryStatus::Delivered, "delivered"),
        2 => (DeliveryStatus::Failed, "failed"),
        _ => (DeliveryStatus::DeadLettered, "dead_lettered"),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let raw = bounded_json(&input.raw_json);

    if let Ok(status) = serde_json::from_slice::<DeliveryStatus>(raw) {
        let canonical = serde_json::to_string(&status).expect("accepted status must serialize");
        let reparsed: DeliveryStatus =
            serde_json::from_str(&canonical).expect("canonical status must parse");
        assert_eq!(reparsed, status);
    }

    if let Ok(value) = serde_json::from_slice::<Value>(raw) {
        let metadata = serde_json::from_value::<EventMetadata>(value.clone());
        let wrapped = serde_json::json!({ "status": value });
        let wrapped_metadata = serde_json::from_value::<EventMetadata>(wrapped);
        let _ = (metadata, wrapped_metadata);
    }

    let (status, expected_name) = generated_status(input.status_choice);
    assert_status_roundtrip(status, expected_name);

    let metadata: EventMetadata =
        serde_json::from_str("{}").expect("missing status must default in EventMetadata");
    assert_eq!(metadata.status, DeliveryStatus::Pending);
});
