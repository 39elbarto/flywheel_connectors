//! Pin the live zone-namespace display and serde tag contract.
//!
//! The RFC sketch names a `ZoneNamespace` struct, while `fcp-core` exposes the
//! implemented namespace surface as `ZoneId` plus the zone-key algorithm tag
//! carried by zone key manifests. This test keeps those concrete wire tokens
//! stable.

use std::error::Error;

use ciborium::Value as CborValue;
use fcp_core::{ZoneId, ZoneIdError, ZoneKeyAlgorithm};
use serde_json::json;

fn canonical_zone_namespace_cases() -> Result<Vec<(&'static str, ZoneId)>, ZoneIdError> {
    Ok(vec![
        ("z:owner", ZoneId::owner()),
        ("z:private", ZoneId::private()),
        ("z:work", ZoneId::work()),
        ("z:project:alpha-beta", "z:project:alpha-beta".parse()?),
        ("z:community", ZoneId::community()),
        ("z:public", ZoneId::public()),
    ])
}

#[test]
fn zone_namespace_display_pins_canonical_zone_ids() -> Result<(), ZoneIdError> {
    for (expected, zone) in canonical_zone_namespace_cases()? {
        assert_eq!(zone.to_string(), expected);
        assert_eq!(format!("{zone}"), expected);
        assert_eq!(zone.as_str(), expected);
    }

    Ok(())
}

#[test]
fn project_zone_namespace_display_roundtrips_through_tailscale_tag() -> Result<(), ZoneIdError> {
    let zone: ZoneId = "z:project:alpha-beta".parse()?;
    let tag = zone.to_tailscale_tag();

    assert_eq!(tag, "tag:fcp-proj-alpha-beta");
    assert_eq!(ZoneId::from_tailscale_tag(&tag)?, zone);
    assert_eq!(
        ZoneId::from_tailscale_tag(&tag)?.to_string(),
        zone.to_string()
    );

    Ok(())
}

#[test]
fn zone_namespace_json_and_cbor_are_scalar_text() -> Result<(), Box<dyn Error>> {
    for (expected, zone) in canonical_zone_namespace_cases()? {
        let json_value = serde_json::to_value(&zone)?;
        assert_eq!(json_value, json!(expected));

        let json_back: ZoneId = serde_json::from_value(json_value)?;
        assert_eq!(json_back, zone);

        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&zone, &mut encoded)?;
        let cbor_value: CborValue = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(cbor_value, CborValue::Text(expected.to_string()));

        let cbor_back: ZoneId = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(cbor_back, zone);
    }

    Ok(())
}

#[test]
fn zone_namespace_key_algorithm_json_tags_are_pinned() -> Result<(), Box<dyn Error>> {
    let cases = [
        (ZoneKeyAlgorithm::ChaCha20Poly1305, "cha_cha20_poly1305"),
        (ZoneKeyAlgorithm::XChaCha20Poly1305, "x_cha_cha20_poly1305"),
    ];

    for (algorithm, expected_tag) in cases {
        let json_value = serde_json::to_value(algorithm)?;
        assert_eq!(json_value, json!(expected_tag));

        let back: ZoneKeyAlgorithm = serde_json::from_value(json_value)?;
        assert_eq!(back, algorithm);
    }

    Ok(())
}

#[test]
fn zone_namespace_key_algorithm_cbor_tags_are_pinned() -> Result<(), Box<dyn Error>> {
    let cases = [
        (ZoneKeyAlgorithm::ChaCha20Poly1305, "cha_cha20_poly1305"),
        (ZoneKeyAlgorithm::XChaCha20Poly1305, "x_cha_cha20_poly1305"),
    ];

    for (algorithm, expected_tag) in cases {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&algorithm, &mut encoded)?;

        let cbor_value: CborValue = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(cbor_value, CborValue::Text(expected_tag.to_string()));

        let back: ZoneKeyAlgorithm = ciborium::de::from_reader(encoded.as_slice())?;
        assert_eq!(back, algorithm);
    }

    Ok(())
}
