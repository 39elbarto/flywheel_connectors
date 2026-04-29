//! Pin the mesh path display/canonical-encoding surface.
//!
//! No type literally named `MeshPath` exists in fcp-core. The public mesh
//! path/preference token surface with Display support is `MeshPlacementHint`,
//! which is the closed vocabulary persisted in placement policy paths.

use fcp_cbor::to_canonical_cbor;
use fcp_core::MeshPlacementHint;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CASES: &[(MeshPlacementHint, &str, &str)] = &[
    (
        MeshPlacementHint::DataLocality,
        "data_locality",
        "6d646174615f6c6f63616c697479",
    ),
    (
        MeshPlacementHint::LowLatency,
        "low_latency",
        "6b6c6f775f6c6174656e6379",
    ),
    (
        MeshPlacementHint::HighResources,
        "high_resources",
        "6e686967685f7265736f7572636573",
    ),
    (
        MeshPlacementHint::SecretReconstructable,
        "secret_reconstructable",
        "767365637265745f7265636f6e73747275637461626c65",
    ),
    (
        MeshPlacementHint::AvoidDerp,
        "avoid_derp",
        "6a61766f69645f64657270",
    ),
];

#[test]
fn mesh_path_display_tokens_are_the_canonical_tokens() -> TestResult {
    for (hint, token, _) in CASES {
        assert_eq!(hint.as_str(), *token);
        assert_eq!(hint.to_string(), *token);
        assert_eq!(serde_json::to_string(hint)?, format!("\"{token}\""));
    }

    Ok(())
}

#[test]
fn mesh_path_canonical_cbor_bytes_are_pinned_and_roundtrip() -> TestResult {
    for (hint, _, expected_hex) in CASES {
        let canonical = to_canonical_cbor(hint)?;
        assert_eq!(hex::encode(&canonical), *expected_hex);

        let decoded: MeshPlacementHint = ciborium::de::from_reader(canonical.as_slice())?;
        assert_eq!(decoded, *hint);
    }

    Ok(())
}

#[test]
fn mesh_path_canonical_encoding_is_deterministic_and_injective() -> TestResult {
    let mut encodings = Vec::new();

    for (hint, _, _) in CASES {
        let first = to_canonical_cbor(hint)?;
        let second = to_canonical_cbor(hint)?;
        assert_eq!(first, second);
        encodings.push((hint, first));
    }

    for (left_index, (left_hint, left_bytes)) in encodings.iter().enumerate() {
        for (right_hint, right_bytes) in encodings.iter().skip(left_index + 1) {
            assert_ne!(
                left_bytes, right_bytes,
                "{left_hint:?} and {right_hint:?} must not share canonical bytes",
            );
        }
    }

    Ok(())
}
