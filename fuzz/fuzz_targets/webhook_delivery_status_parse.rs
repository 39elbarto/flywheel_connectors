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

const MAX_JSON_BYTES: usize = 64 * 1024;
const OVERSIZED_STATUS_LEN: usize = 16 * 1024;

#[derive(Arbitrary, Debug)]
struct Input {
    raw_json: Vec<u8>,
    status_choice: u8,
}

fn bounded_json(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_JSON_BYTES)]
}

fn assert_status_parse(input: &str, expected: DeliveryStatus) {
    let parsed: DeliveryStatus =
        serde_json::from_str(input).expect("known DeliveryStatus variant must parse");
    assert_eq!(parsed, expected);
}

fn assert_status_rejected(input: &str) {
    assert!(
        serde_json::from_str::<DeliveryStatus>(input).is_err(),
        "invalid DeliveryStatus JSON unexpectedly parsed: {input}"
    );
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

fn exercise_fixed_boundaries() {
    assert_status_parse(r#""pending""#, DeliveryStatus::Pending);
    assert_status_parse(r#""delivered""#, DeliveryStatus::Delivered);
    assert_status_parse(r#""failed""#, DeliveryStatus::Failed);
    assert_status_parse(r#""dead_lettered""#, DeliveryStatus::DeadLettered);

    assert_status_rejected(r#""unknown""#);
    assert_status_rejected(r#""dead-lettered""#);
    assert_status_rejected(r#""PENDING""#);
    assert_status_rejected("null");
    assert_status_rejected("{}");
    assert_status_rejected(r#""pending"#);
    assert_status_rejected("[");

    let metadata: EventMetadata =
        serde_json::from_str("{}").expect("missing status must default in EventMetadata");
    assert_eq!(metadata.status, DeliveryStatus::Pending);

    let metadata: EventMetadata = serde_json::from_str(r#"{"status":"delivered"}"#)
        .expect("known EventMetadata.status must parse");
    assert_eq!(metadata.status, DeliveryStatus::Delivered);

    assert!(
        serde_json::from_str::<EventMetadata>(r#"{"status":"unknown"}"#).is_err(),
        "unknown EventMetadata.status must not default"
    );
    assert!(
        serde_json::from_str::<EventMetadata>(r#"{"status":null}"#).is_err(),
        "explicit null EventMetadata.status must not default"
    );
    assert!(
        serde_json::from_str::<EventMetadata>(r#"{"status":"pending""#).is_err(),
        "malformed EventMetadata JSON must be rejected"
    );
}

fuzz_target!(|data: &[u8]| {
    exercise_fixed_boundaries();

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

    let unknown_status = String::from_utf8_lossy(raw);
    let unknown_status_json = serde_json::json!(unknown_status.as_ref()).to_string();
    if !matches!(
        unknown_status.as_ref(),
        "pending" | "delivered" | "failed" | "dead_lettered"
    ) {
        assert_status_rejected(&unknown_status_json);
    }

    let oversized_unknown = format!("\"{}\"", "x".repeat(OVERSIZED_STATUS_LEN));
    assert_status_rejected(&oversized_unknown);
    assert!(
        serde_json::from_str::<EventMetadata>(&format!(r#"{{"status":{oversized_unknown}}}"#))
            .is_err(),
        "oversized unknown EventMetadata.status must be rejected"
    );

    let (status, expected_name) = generated_status(input.status_choice);
    assert_status_roundtrip(status, expected_name);
});
