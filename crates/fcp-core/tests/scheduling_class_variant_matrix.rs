//! Pin the fcp-core scheduling-class variant matrix.
//!
//! fcp-core does not expose a type named `SchedulingClass`; the public
//! scheduling preference surface is `MeshPlacementHint`. This test pins that
//! scheduling-class-like enum's variants, Display tokens, and serde tags.

use std::collections::HashSet;

use fcp_core::MeshPlacementHint;

const SCHEDULING_CLASSES: &[(MeshPlacementHint, &str)] = &[
    (MeshPlacementHint::DataLocality, "data_locality"),
    (MeshPlacementHint::LowLatency, "low_latency"),
    (MeshPlacementHint::HighResources, "high_resources"),
    (
        MeshPlacementHint::SecretReconstructable,
        "secret_reconstructable",
    ),
    (MeshPlacementHint::AvoidDerp, "avoid_derp"),
];

#[test]
fn scheduling_class_display_tokens_match_stable_serde_tags() {
    for (class, tag) in SCHEDULING_CLASSES {
        assert_eq!(class.as_str(), *tag);
        assert_eq!(class.to_string(), *tag);
        assert_eq!(format!("{class}"), *tag);
        assert_eq!(
            serde_json::to_string(class).expect("serialize scheduling class"),
            format!("\"{tag}\"")
        );
    }
}

#[test]
fn scheduling_class_json_roundtrips_each_variant() {
    for (class, tag) in SCHEDULING_CLASSES {
        let json = format!("\"{tag}\"");
        let decoded: MeshPlacementHint =
            serde_json::from_str(&json).expect("deserialize scheduling class");

        assert_eq!(decoded, *class);
    }
}

#[test]
fn scheduling_class_cbor_roundtrips_each_variant() {
    for (class, _) in SCHEDULING_CLASSES {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(class, &mut encoded).expect("encode scheduling class");
        let decoded: MeshPlacementHint =
            ciborium::de::from_reader(encoded.as_slice()).expect("decode scheduling class");

        assert_eq!(decoded, *class);
    }
}

#[test]
fn scheduling_class_variants_and_display_tokens_are_distinct() {
    for (index, (left, _)) in SCHEDULING_CLASSES.iter().enumerate() {
        for (right, _) in &SCHEDULING_CLASSES[index + 1..] {
            assert_ne!(left, right);
        }
    }

    let display_tokens: HashSet<&'static str> =
        SCHEDULING_CLASSES.iter().map(|(_, tag)| *tag).collect();

    assert_eq!(display_tokens.len(), SCHEDULING_CLASSES.len());
}

#[test]
fn scheduling_class_variant_count_is_pinned() {
    assert_eq!(SCHEDULING_CLASSES.len(), 5);
}
