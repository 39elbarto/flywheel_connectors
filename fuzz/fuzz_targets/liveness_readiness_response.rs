#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, Utc};
use fcp_core::{LivenessResponse, ReadinessResponse};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

const MAX_COMPONENTS: usize = 16;
const MAX_NAME_BYTES: usize = 64;

#[derive(Arbitrary, Debug)]
struct Input {
    alive: bool,
    ready: bool,
    timestamp_secs: i64,
    timestamp_nanos: u32,
    components: Vec<ComponentInput>,
}

#[derive(Arbitrary, Debug)]
struct ComponentInput {
    name: Vec<u8>,
    ready: bool,
}

fn bounded_name(bytes: &[u8], index: usize) -> String {
    let value = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_NAME_BYTES)]).into_owned();
    if value.is_empty() {
        format!("component-{index}")
    } else {
        value
    }
}

fn bounded_timestamp(secs: i64, nanos: u32) -> DateTime<Utc> {
    DateTime::from_timestamp(secs % 4_102_444_800, nanos % 1_000_000_000)
        .unwrap_or(DateTime::UNIX_EPOCH)
}

fn readiness_components(input: &[ComponentInput]) -> HashMap<String, bool> {
    input
        .iter()
        .take(MAX_COMPONENTS)
        .enumerate()
        .map(|(index, component)| (bounded_name(&component.name, index), component.ready))
        .collect()
}

fn assert_liveness_roundtrip(response: &LivenessResponse) {
    let json = serde_json::to_string(response).expect("LivenessResponse must serialize to JSON");
    assert_eq!(
        serde_json::from_str::<LivenessResponse>(&json)
            .expect("serialized LivenessResponse must deserialize")
            .alive,
        response.alive
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(response, &mut cbor).expect("LivenessResponse must serialize to CBOR");
    let decoded: LivenessResponse =
        ciborium::from_reader(&cbor[..]).expect("serialized LivenessResponse must deserialize");
    assert_eq!(decoded.alive, response.alive);
    assert_eq!(decoded.timestamp, response.timestamp);
}

fn assert_readiness_roundtrip(response: &ReadinessResponse) {
    let json = serde_json::to_string(response).expect("ReadinessResponse must serialize to JSON");
    let decoded_json: ReadinessResponse =
        serde_json::from_str(&json).expect("serialized ReadinessResponse must deserialize");
    assert_eq!(decoded_json.ready, response.ready);
    assert_eq!(decoded_json.components, response.components);
    assert_eq!(decoded_json.timestamp, response.timestamp);

    let mut cbor = Vec::new();
    ciborium::into_writer(response, &mut cbor).expect("ReadinessResponse must serialize to CBOR");
    let decoded_cbor: ReadinessResponse =
        ciborium::from_reader(&cbor[..]).expect("serialized ReadinessResponse must deserialize");
    assert_eq!(decoded_cbor.ready, response.ready);
    assert_eq!(decoded_cbor.components, response.components);
    assert_eq!(decoded_cbor.timestamp, response.timestamp);
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let timestamp = bounded_timestamp(input.timestamp_secs, input.timestamp_nanos);
    let liveness = LivenessResponse {
        alive: input.alive,
        timestamp,
    };
    assert_liveness_roundtrip(&liveness);

    let readiness = ReadinessResponse {
        ready: input.ready,
        components: readiness_components(&input.components),
        timestamp,
    };
    assert!(readiness.components.len() <= MAX_COMPONENTS);
    assert_readiness_roundtrip(&readiness);
});
