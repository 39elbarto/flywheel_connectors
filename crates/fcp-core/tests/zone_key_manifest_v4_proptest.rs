//! `ZoneKeyManifest` V4 CBOR-deserialisation fuzz harness via proptest.
//!
//! Goal: prove that arbitrary byte streams fed into the V4
//! `ZoneKeyManifest` deserialiser NEVER panic, NEVER hang, and ALWAYS
//! return a typed `Result`. This is the most-attacked surface of the
//! V4 schema migration (br-kyopb.1.2.3) — an attacker can drop
//! tampered manifests onto disk or post them to a future admin
//! endpoint, and the parser must hold up.

use fcp_core::{
    ZoneKeyManifest, WrappedKey, WrappedZoneKeyV4, ZoneKemAlgorithm,
};
use proptest::prelude::*;

// ── Targeted regression cases ───────────────────────────────────────

#[test]
fn zone_key_manifest_v4_empty_bytes_is_decisive_err() {
    let result = std::panic::catch_unwind(|| {
        ciborium::from_reader::<ZoneKeyManifest, _>(&[][..])
    });
    assert!(result.is_ok(), "deserialise panicked on empty input");
    assert!(result.unwrap().is_err());
}

#[test]
fn zone_key_manifest_v4_zone_kem_algorithm_arbitrary_string_is_typed_err() {
    // Deserialising a non-recognised kem string into ZoneKemAlgorithm
    // must surface a serde error, not a panic.
    let result = std::panic::catch_unwind(|| {
        serde_json::from_str::<ZoneKemAlgorithm>(r#""nonsense_kem""#)
    });
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
}

#[test]
fn zone_key_manifest_v4_wrapped_key_unknown_kem_tag_is_typed_err() {
    // WrappedKey is a tagged enum. An unknown tag value must produce a
    // serde error, not a panic.
    let json = r#"{"kem":"nonexistent_variant","sealed":{"enc":"00","ciphertext":"00"}}"#;
    let result = std::panic::catch_unwind(|| serde_json::from_str::<WrappedKey>(json));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
}

#[test]
fn zone_key_manifest_v4_wrapped_key_missing_sealed_field_is_typed_err() {
    let json = r#"{"kem":"hpke_x25519"}"#;
    let result = std::panic::catch_unwind(|| serde_json::from_str::<WrappedKey>(json));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
}

// ── Proptest randomised harness ─────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    /// Arbitrary byte stream → ZoneKeyManifest deserialise: never
    /// panic. Either decode succeeds (vanishingly rare) or returns a
    /// typed serde error.
    #[test]
    fn zone_key_manifest_v4_arbitrary_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=4096),
    ) {
        let result = std::panic::catch_unwind(|| {
            ciborium::from_reader::<ZoneKeyManifest, _>(bytes.as_slice())
        });
        prop_assert!(
            result.is_ok(),
            "ZoneKeyManifest CBOR deserialise panicked on {}-byte input",
            bytes.len()
        );
    }

    /// Arbitrary byte stream → WrappedKey deserialise: never panic.
    /// This is the per-recipient enum that V4 manifests carry; it's
    /// the hottest decoding loop in a multi-recipient manifest.
    #[test]
    fn zone_key_manifest_v4_wrapped_key_arbitrary_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=2048),
    ) {
        let result = std::panic::catch_unwind(|| {
            ciborium::from_reader::<WrappedKey, _>(bytes.as_slice())
        });
        prop_assert!(
            result.is_ok(),
            "WrappedKey CBOR deserialise panicked on {}-byte input",
            bytes.len()
        );
    }

    /// Arbitrary byte stream → WrappedZoneKeyV4 deserialise: never
    /// panic.
    #[test]
    fn zone_key_manifest_v4_wrapped_zone_key_v4_arbitrary_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=2048),
    ) {
        let result = std::panic::catch_unwind(|| {
            ciborium::from_reader::<WrappedZoneKeyV4, _>(bytes.as_slice())
        });
        prop_assert!(result.is_ok());
    }

    /// Arbitrary byte stream → ZoneKemAlgorithm deserialise: never
    /// panic. The smallest leaf — if even THIS panics, every encloser
    /// is poisoned.
    #[test]
    fn zone_key_manifest_v4_zone_kem_algorithm_arbitrary_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=64),
    ) {
        let result = std::panic::catch_unwind(|| {
            ciborium::from_reader::<ZoneKemAlgorithm, _>(bytes.as_slice())
        });
        prop_assert!(result.is_ok());
    }

    /// Arbitrary JSON for the same surfaces — proptest doesn't
    /// generate valid JSON cheaply, so we use the same byte strategy
    /// and let the deserialiser reject most of them. The point is
    /// that the JSON path also has zero panics.
    #[test]
    fn zone_key_manifest_v4_arbitrary_json_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=4096),
    ) {
        let result = std::panic::catch_unwind(|| {
            serde_json::from_slice::<ZoneKeyManifest>(&bytes)
        });
        prop_assert!(
            result.is_ok(),
            "ZoneKeyManifest JSON deserialise panicked on {}-byte input",
            bytes.len()
        );
    }

    /// Arbitrary string variants for ZoneKemAlgorithm via JSON: only
    /// the two pinned snake_case labels deserialise; everything else
    /// must be a clean serde error, never a panic.
    #[test]
    fn zone_key_manifest_v4_zone_kem_algorithm_arbitrary_string_never_panics(
        s in "[\\PC]{0,32}",  // any non-control unicode, up to 32 chars
    ) {
        let json = format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let result = std::panic::catch_unwind(|| {
            serde_json::from_str::<ZoneKemAlgorithm>(&json)
        });
        prop_assert!(result.is_ok(), "ZoneKemAlgorithm panicked on string {s:?}");
        let outcome = result.unwrap();
        match s.as_str() {
            "hpke_x25519" => prop_assert!(matches!(outcome, Ok(ZoneKemAlgorithm::HpkeX25519))),
            "x_wing" => prop_assert!(matches!(outcome, Ok(ZoneKemAlgorithm::XWing))),
            _ => prop_assert!(outcome.is_err()),
        }
    }
}
