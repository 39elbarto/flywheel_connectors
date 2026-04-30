//! Pin the public `ConnectorMetrics` Display and serde contract.
//!
//! Bead `flywheel_connectors-yt4xi` asks for `ConnectorMetric` Display +
//! serde coverage. There is no singular `ConnectorMetric` type in fcp-core;
//! the public connector telemetry surface is [`ConnectorMetrics`].

use ciborium::Value as CborValue;
use fcp_core::ConnectorMetrics;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sample_metrics() -> ConnectorMetrics {
    ConnectorMetrics {
        requests_total: 17,
        requests_success: 15,
        requests_error: 2,
        connections_active: 3,
        events_emitted: 4,
        latency_p50_ms: 25,
        latency_p99_ms: 250,
        bytes_sent: 4096,
        bytes_received: 8192,
    }
}

fn assert_metrics_eq(actual: &ConnectorMetrics, expected: &ConnectorMetrics) {
    assert_eq!(actual.requests_total, expected.requests_total);
    assert_eq!(actual.requests_success, expected.requests_success);
    assert_eq!(actual.requests_error, expected.requests_error);
    assert_eq!(actual.connections_active, expected.connections_active);
    assert_eq!(actual.events_emitted, expected.events_emitted);
    assert_eq!(actual.latency_p50_ms, expected.latency_p50_ms);
    assert_eq!(actual.latency_p99_ms, expected.latency_p99_ms);
    assert_eq!(actual.bytes_sent, expected.bytes_sent);
    assert_eq!(actual.bytes_received, expected.bytes_received);
}

#[test]
fn connector_metrics_display_is_stable_key_value_sequence() {
    let metrics = sample_metrics();

    assert_eq!(
        metrics.to_string(),
        "requests_total=17 requests_success=15 requests_error=2 connections_active=3 events_emitted=4 latency_p50_ms=25 latency_p99_ms=250 bytes_sent=4096 bytes_received=8192"
    );
}

#[test]
fn connector_metrics_json_shape_and_roundtrip_are_pinned() -> TestResult {
    let metrics = sample_metrics();
    let json = serde_json::to_value(&metrics)?;

    assert_eq!(
        json,
        json!({
            "requests_total": 17,
            "requests_success": 15,
            "requests_error": 2,
            "connections_active": 3,
            "events_emitted": 4,
            "latency_p50_ms": 25,
            "latency_p99_ms": 250,
            "bytes_sent": 4096,
            "bytes_received": 8192
        })
    );

    let decoded: ConnectorMetrics = serde_json::from_value(json)?;
    assert_metrics_eq(&decoded, &metrics);
    assert_eq!(decoded.to_string(), metrics.to_string());
    Ok(())
}

#[test]
fn connector_metrics_cbor_roundtrip_preserves_fields() -> TestResult {
    let metrics = sample_metrics();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&metrics, &mut bytes)?;

    let decoded: ConnectorMetrics = ciborium::de::from_reader(bytes.as_slice())?;
    assert_metrics_eq(&decoded, &metrics);
    assert_eq!(decoded.to_string(), metrics.to_string());
    Ok(())
}

#[test]
fn connector_metrics_cbor_encodes_as_nine_field_map() -> TestResult {
    let metrics = sample_metrics();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&metrics, &mut bytes)?;

    let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
    let entries = match value {
        CborValue::Map(entries) => entries,
        other => {
            return Err(
                format!("ConnectorMetrics must encode as a CBOR map, got {other:?}").into(),
            );
        }
    };

    let mut keys = Vec::with_capacity(entries.len());
    for (key, _) in &entries {
        let CborValue::Text(text) = key else {
            return Err(format!("ConnectorMetrics CBOR keys must be text, got {key:?}").into());
        };
        keys.push(text.as_str());
    }

    assert_eq!(
        keys,
        [
            "requests_total",
            "requests_success",
            "requests_error",
            "connections_active",
            "events_emitted",
            "latency_p50_ms",
            "latency_p99_ms",
            "bytes_sent",
            "bytes_received",
        ]
    );
    Ok(())
}
