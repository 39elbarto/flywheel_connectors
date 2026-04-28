#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ConnectorHealth, HealthSnapshot, HealthState, RateLimitStatus};
use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    state: u8,
    reason: Vec<u8>,
    uptime_ms: u64,
    load_millis: Option<u16>,
    include_details: bool,
    rate_limit: Option<RateLimitInput>,
}

#[derive(Arbitrary, Debug)]
struct RateLimitInput {
    limit: u32,
    remaining: u32,
    reset_at: u64,
    window_seconds: u32,
}

fn bounded_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_TEXT_BYTES)]).into_owned()
}

fn health_state(selector: u8, reason: String) -> HealthState {
    match selector % 5 {
        0 => HealthState::Starting,
        1 => HealthState::Ready,
        2 => HealthState::Degraded { reason },
        3 => HealthState::Error { reason },
        _ => HealthState::Stopping,
    }
}

fn snapshot_from(input: &Input) -> HealthSnapshot {
    let reason = bounded_lossy(&input.reason);
    HealthSnapshot {
        status: health_state(input.state, reason.clone()),
        uptime_ms: input.uptime_ms,
        load: input
            .load_millis
            .map(|load| f32::from(load.min(1_000)) / 1_000.0),
        details: input
            .include_details
            .then(|| serde_json::json!({ "reason": reason })),
        rate_limit: input.rate_limit.as_ref().map(|status| RateLimitStatus {
            limit: status.limit,
            remaining: status.remaining,
            reset_at: status.reset_at,
            window_seconds: status.window_seconds,
        }),
    }
}

fn assert_snapshot_semantics(snapshot: &HealthSnapshot) {
    match &snapshot.status {
        HealthState::Ready => {
            assert!(snapshot.is_ready());
            assert!(snapshot.is_healthy());
        }
        HealthState::Degraded { reason } => {
            assert!(!snapshot.is_ready());
            assert!(snapshot.is_healthy());
            assert!(matches!(
                ConnectorHealth::from(&snapshot.status),
                ConnectorHealth::Degraded { reason: converted } if converted == *reason
            ));
        }
        HealthState::Error { reason } => {
            assert!(!snapshot.is_ready());
            assert!(!snapshot.is_healthy());
            assert!(matches!(
                ConnectorHealth::from(&snapshot.status),
                ConnectorHealth::Unavailable { reason: converted, .. } if converted == *reason
            ));
        }
        HealthState::Starting | HealthState::Stopping => {
            assert!(!snapshot.is_ready());
            assert!(!snapshot.is_healthy());
            assert!(matches!(
                ConnectorHealth::from(&snapshot.status),
                ConnectorHealth::Unavailable { .. }
            ));
        }
    }

    if let Some(rate_limit) = &snapshot.rate_limit {
        assert_eq!(rate_limit.is_limited(), rate_limit.remaining == 0);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let snapshot = snapshot_from(&input);
    assert_snapshot_semantics(&snapshot);

    let json = serde_json::to_string(&snapshot).expect("HealthSnapshot must serialize to JSON");
    let json_roundtrip: HealthSnapshot =
        serde_json::from_str(&json).expect("serialized HealthSnapshot must deserialize");
    assert_snapshot_semantics(&json_roundtrip);

    let mut cbor = Vec::new();
    ciborium::into_writer(&snapshot, &mut cbor).expect("HealthSnapshot must serialize to CBOR");
    let cbor_roundtrip: HealthSnapshot =
        ciborium::from_reader(&cbor[..]).expect("serialized HealthSnapshot must deserialize");
    assert_snapshot_semantics(&cbor_roundtrip);
});
