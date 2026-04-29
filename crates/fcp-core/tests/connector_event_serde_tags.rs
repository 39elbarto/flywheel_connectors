use ciborium::value::Value as CborValue;
use fcp_core::{
    ConnectorEvent, ConnectorId, EventAck, EventData, EventEnvelope, EventNack, Principal,
    TrustLevel, ZoneId,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn sample_principal() -> Principal {
    Principal {
        kind: "user".to_string(),
        id: "alice".to_string(),
        trust: TrustLevel::Paired,
        display: Some("Alice".to_string()),
    }
}

fn sample_data() -> EventData {
    EventData::new(
        ConnectorId::from_static("test:streaming:v1"),
        "inst_events".parse().expect("valid instance id"),
        ZoneId::work(),
        sample_principal(),
        json!({"action": "created", "resource": "document"}),
    )
}

fn sample_envelope() -> EventEnvelope {
    let mut envelope = EventEnvelope::new("events.documents", sample_data())
        .with_seq(42)
        .with_cursor("cursor-42")
        .requiring_ack();
    envelope.timestamp = "2026-04-29T01:02:03Z".parse().expect("valid timestamp");
    envelope
}

fn cbor_tag(value: &CborValue) -> TestResult<&str> {
    let CborValue::Map(entries) = value else {
        return Err("ConnectorEvent CBOR must be an externally-tagged map".into());
    };
    assert_eq!(entries.len(), 1);
    let CborValue::Text(tag) = &entries[0].0 else {
        return Err("ConnectorEvent CBOR tag key must be text".into());
    };
    Ok(tag.as_str())
}

fn assert_json_tag(value: &ConnectorEvent, expected_tag: &str) -> TestResult<serde_json::Value> {
    let encoded = serde_json::to_value(value)?;
    let object = encoded
        .as_object()
        .ok_or("ConnectorEvent JSON must be an externally-tagged object")?;
    assert_eq!(object.len(), 1);
    assert!(object.contains_key(expected_tag), "{encoded}");
    Ok(encoded)
}

fn assert_cbor_tag(value: &ConnectorEvent, expected_tag: &str) -> TestResult<()> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    let decoded_value: CborValue = ciborium::from_reader(encoded.as_slice())?;
    assert_eq!(cbor_tag(&decoded_value)?, expected_tag);
    let _: ConnectorEvent = ciborium::from_reader(encoded.as_slice())?;
    Ok(())
}

#[test]
fn connector_event_envelope_json_and_cbor_tag_roundtrip() -> TestResult {
    let event = ConnectorEvent::Envelope(sample_envelope());

    let encoded = assert_json_tag(&event, "envelope")?;
    let decoded: ConnectorEvent = serde_json::from_value(encoded)?;
    let ConnectorEvent::Envelope(envelope) = decoded else {
        return Err("decoded ConnectorEvent tag should be envelope".into());
    };
    assert_eq!(envelope.topic, "events.documents");
    assert_eq!(envelope.seq, 42);
    assert_eq!(envelope.cursor, "cursor-42");
    assert!(envelope.requires_ack);

    assert_cbor_tag(&event, "envelope")?;
    Ok(())
}

#[test]
fn connector_event_ack_json_and_cbor_tag_roundtrip() -> TestResult {
    let event = ConnectorEvent::Ack(
        EventAck::new("events.documents", vec![42]).with_cursors(vec!["cursor-42".to_string()]),
    );

    let encoded = assert_json_tag(&event, "ack")?;
    let decoded: ConnectorEvent = serde_json::from_value(encoded)?;
    let ConnectorEvent::Ack(ack) = decoded else {
        return Err("decoded ConnectorEvent tag should be ack".into());
    };
    assert_eq!(ack.r#type, "ack");
    assert_eq!(ack.topic, "events.documents");
    assert_eq!(ack.seqs, vec![42]);
    assert_eq!(ack.cursors, vec!["cursor-42"]);

    assert_cbor_tag(&event, "ack")?;
    Ok(())
}

#[test]
fn connector_event_nack_json_and_cbor_tag_roundtrip() -> TestResult {
    let event = ConnectorEvent::Nack(
        EventNack::new("events.documents", vec![42], "temporary failure").with_delay(250),
    );

    let encoded = assert_json_tag(&event, "nack")?;
    let decoded: ConnectorEvent = serde_json::from_value(encoded)?;
    let ConnectorEvent::Nack(nack) = decoded else {
        return Err("decoded ConnectorEvent tag should be nack".into());
    };
    assert_eq!(nack.r#type, "nack");
    assert_eq!(nack.topic, "events.documents");
    assert_eq!(nack.seqs, vec![42]);
    assert_eq!(nack.reason, "temporary failure");
    assert_eq!(nack.delay_ms, Some(250));

    assert_cbor_tag(&event, "nack")?;
    Ok(())
}
