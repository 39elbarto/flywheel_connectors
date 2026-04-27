#![no_main]
//! Amplitude response-body deserializer fuzz target.
//!
//! Exercises the typed JSON boundary used after successful Amplitude HTTP
//! responses and the error response body parser shape without reaching the
//! network client.

use arbitrary::{Arbitrary, Unstructured};
use fcp_amplitude::types::{
    ApiErrorResponse, ChartQueryResponse, Cohort, CohortsListResponse, EventsExportResponse,
    ExportedEvent,
};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde_json::{Value, json};

const MAX_RAW_JSON_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_VALUES: usize = 16;

#[derive(Arbitrary, Debug)]
struct AmplitudeResponseFuzz<'a> {
    mode: u8,
    raw_json: &'a [u8],
    text_a: &'a [u8],
    text_b: &'a [u8],
    number: i64,
    flag: bool,
    values: Vec<&'a [u8]>,
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

fn bounded_strings(values: &[&[u8]]) -> Vec<String> {
    values
        .iter()
        .take(MAX_VALUES)
        .map(|value| lossy_field(value))
        .collect()
}

fn bounded_values(values: &[&[u8]]) -> Vec<Value> {
    values
        .iter()
        .take(MAX_VALUES)
        .map(|value| json!({"value": lossy_field(value)}))
        .collect()
}

fn structured_value(input: &AmplitudeResponseFuzz<'_>) -> Value {
    let text_a = lossy_field(input.text_a);
    let text_b = lossy_field(input.text_b);
    let values = bounded_values(&input.values);

    match input.mode % 6 {
        0 => json!({
            "data": {"series": values},
            "xValues": bounded_strings(&input.values),
            "seriesLabels": [text_a],
            "seriesCollapsed": [[input.number, text_b]],
        }),
        1 => json!({
            "id": text_a,
            "name": text_b,
            "appId": input.number,
            "published": input.flag,
            "archived": !input.flag,
            "size": input.number,
        }),
        2 => json!({ "cohorts": values }),
        3 => json!({
            "event_type": text_a,
            "event_time": text_b,
            "user_id": lossy_field(input.text_a),
            "session_id": input.number,
            "event_properties": {"fuzz": values},
            "user_properties": {"flag": input.flag},
        }),
        4 => json!({ "data": values }),
        _ => json!({
            "error": text_a,
            "message": text_b,
            "code": input.number,
        }),
    }
}

fn roundtrip<T>(value: Value)
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if let Ok(parsed) = serde_json::from_value::<T>(value) {
        if let Ok(encoded) = serde_json::to_value(&parsed) {
            let _ = serde_json::from_value::<T>(encoded);
        }
    }
}

fn exercise_value(value: Value) {
    roundtrip::<ChartQueryResponse>(value.clone());
    roundtrip::<Cohort>(value.clone());
    roundtrip::<CohortsListResponse>(value.clone());
    roundtrip::<ExportedEvent>(value.clone());
    roundtrip::<EventsExportResponse>(value.clone());
    let _ = serde_json::from_value::<ApiErrorResponse>(value);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = Unstructured::new(data).arbitrary::<AmplitudeResponseFuzz<'_>>() {
        match input.mode % 2 {
            0 => {
                if let Ok(value) =
                    serde_json::from_slice::<Value>(bounded(input.raw_json, MAX_RAW_JSON_BYTES))
                {
                    exercise_value(value);
                }
            }
            _ => exercise_value(structured_value(&input)),
        }
    } else if let Ok(value) = serde_json::from_slice::<Value>(bounded(data, MAX_RAW_JSON_BYTES)) {
        exercise_value(value);
    }
});
