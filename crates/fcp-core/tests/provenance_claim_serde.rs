//! Pin the provenance-claim serde shape.
//!
//! fcp-core has no public type literally named `ProvenanceClaim`; the public
//! claim payload for request/object provenance is `Provenance`.

use ciborium::value::Value as CborValue;
use fcp_core::{Provenance, ProvenanceStep, TaintLevel, ZoneId};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn zone(id: &str) -> TestResult<ZoneId> {
    Ok(ZoneId::try_from(id.to_owned())?)
}

fn full_provenance_claim() -> TestResult<Provenance> {
    Ok(Provenance::highly_tainted(zone("z:work")?)
        .with_step(ProvenanceStep {
            timestamp_ms: 1_775_000_000_001,
            zone: zone("z:work")?,
            actor: "agent:cod3".to_owned(),
            action: "connector.invoke".to_owned(),
            resource: "capability:github.issues.read".to_owned(),
        })
        .with_step(ProvenanceStep {
            timestamp_ms: 1_775_000_000_777,
            zone: zone("z:project:alpha")?,
            actor: "connector:github".to_owned(),
            action: "result.materialize".to_owned(),
            resource: "object:issue-42".to_owned(),
        })
        .elevated_with("approval-token-provenance-claim"))
}

fn assert_same_provenance(actual: &Provenance, expected: &Provenance) {
    assert_eq!(actual.origin_zone.as_str(), expected.origin_zone.as_str());
    assert_eq!(actual.taint, expected.taint);
    assert_eq!(actual.elevated, expected.elevated);
    assert_eq!(actual.elevation_token, expected.elevation_token);
    assert_eq!(actual.chain.len(), expected.chain.len());

    for (actual_step, expected_step) in actual.chain.iter().zip(&expected.chain) {
        assert_eq!(actual_step.timestamp_ms, expected_step.timestamp_ms);
        assert_eq!(actual_step.zone.as_str(), expected_step.zone.as_str());
        assert_eq!(actual_step.actor, expected_step.actor);
        assert_eq!(actual_step.action, expected_step.action);
        assert_eq!(actual_step.resource, expected_step.resource);
    }
}

fn cbor_map(value: &CborValue) -> TestResult<&[(CborValue, CborValue)]> {
    match value {
        CborValue::Map(entries) => Ok(entries.as_slice()),
        other => Err(test_error(format!("expected CBOR map, got {other:?}"))),
    }
}

fn cbor_field<'a>(entries: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    entries
        .iter()
        .find_map(|(entry_key, value)| match entry_key {
            CborValue::Text(text) if text == key => Some(value),
            _ => None,
        })
}

#[test]
fn provenance_claim_json_roundtrip_preserves_full_shape() -> TestResult {
    let claim = full_provenance_claim()?;

    let value = serde_json::to_value(&claim)?;
    assert_eq!(
        value,
        serde_json::json!({
            "origin_zone": "z:work",
            "chain": [
                {
                    "timestamp_ms": 1_775_000_000_001_u64,
                    "zone": "z:work",
                    "actor": "agent:cod3",
                    "action": "connector.invoke",
                    "resource": "capability:github.issues.read",
                },
                {
                    "timestamp_ms": 1_775_000_000_777_u64,
                    "zone": "z:project:alpha",
                    "actor": "connector:github",
                    "action": "result.materialize",
                    "resource": "object:issue-42",
                },
            ],
            "taint": "HighlyTainted",
            "elevated": true,
            "elevation_token": "approval-token-provenance-claim",
        })
    );

    let encoded = serde_json::to_string(&claim)?;
    let decoded: Provenance = serde_json::from_str(&encoded)?;
    assert_same_provenance(&decoded, &claim);

    Ok(())
}

#[test]
fn provenance_claim_cbor_roundtrip_preserves_full_shape() -> TestResult {
    let claim = full_provenance_claim()?;

    let mut bytes = Vec::new();
    ciborium::into_writer(&claim, &mut bytes)?;

    let value: CborValue = ciborium::from_reader(bytes.as_slice())?;
    let entries = cbor_map(&value)?;
    assert_eq!(entries.len(), 5);
    assert_eq!(
        cbor_field(entries, "origin_zone"),
        Some(&CborValue::Text("z:work".to_owned()))
    );
    assert_eq!(
        cbor_field(entries, "taint"),
        Some(&CborValue::Text("HighlyTainted".to_owned()))
    );
    assert_eq!(
        cbor_field(entries, "elevated"),
        Some(&CborValue::Bool(true))
    );
    assert_eq!(
        cbor_field(entries, "elevation_token"),
        Some(&CborValue::Text(
            "approval-token-provenance-claim".to_owned()
        ))
    );

    let chain = match cbor_field(entries, "chain") {
        Some(CborValue::Array(chain)) => chain,
        Some(other) => return Err(test_error(format!("expected chain array, got {other:?}"))),
        None => return Err(test_error("missing chain field")),
    };
    assert_eq!(chain.len(), 2);

    let decoded: Provenance = ciborium::from_reader(bytes.as_slice())?;
    assert_same_provenance(&decoded, &claim);

    let mut reencoded = Vec::new();
    ciborium::into_writer(&decoded, &mut reencoded)?;
    assert_eq!(reencoded, bytes);

    Ok(())
}

#[test]
fn provenance_claim_defaults_roundtrip_without_elevation_token() -> TestResult {
    let claim = Provenance::new(zone("z:public")?);

    let json = serde_json::to_value(&claim)?;
    assert_eq!(json.get("elevation_token"), None);
    assert_eq!(
        json.get("origin_zone"),
        Some(&serde_json::json!("z:public"))
    );
    assert_eq!(json.get("chain"), Some(&serde_json::json!([])));
    assert_eq!(json.get("taint"), Some(&serde_json::json!("Untainted")));
    assert_eq!(json.get("elevated"), Some(&serde_json::json!(false)));

    let json_decoded: Provenance = serde_json::from_value(json)?;
    assert_same_provenance(&json_decoded, &claim);

    let mut cbor = Vec::new();
    ciborium::into_writer(&claim, &mut cbor)?;
    let cbor_decoded: Provenance = ciborium::from_reader(cbor.as_slice())?;
    assert_same_provenance(&cbor_decoded, &claim);

    Ok(())
}
