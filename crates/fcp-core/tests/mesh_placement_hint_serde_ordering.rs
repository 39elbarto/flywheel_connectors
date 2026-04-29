use fcp_core::MeshPlacementHint;

const ASCENDING: [MeshPlacementHint; 5] = [
    MeshPlacementHint::DataLocality,
    MeshPlacementHint::LowLatency,
    MeshPlacementHint::HighResources,
    MeshPlacementHint::SecretReconstructable,
    MeshPlacementHint::AvoidDerp,
];

const SERDE_TAGS: [(MeshPlacementHint, &str); 5] = [
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
fn json_serde_uses_snake_case_tags_for_each_hint() {
    for (hint, expected_tag) in SERDE_TAGS {
        let json = serde_json::to_string(&hint).expect("serialize mesh placement hint");
        assert_eq!(json, format!("\"{expected_tag}\""));

        let decoded: MeshPlacementHint =
            serde_json::from_str(&json).expect("deserialize mesh placement hint");
        assert_eq!(decoded, hint);
    }
}

#[test]
fn cbor_roundtrip_preserves_each_hint_variant() {
    for hint in ASCENDING {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&hint, &mut encoded).expect("encode mesh placement hint");

        let decoded: MeshPlacementHint =
            ciborium::de::from_reader(encoded.as_slice()).expect("decode mesh placement hint");
        assert_eq!(decoded, hint);
    }
}

#[test]
fn ordering_is_total_and_matches_declared_preference_order() {
    let mut shuffled = [
        MeshPlacementHint::AvoidDerp,
        MeshPlacementHint::HighResources,
        MeshPlacementHint::DataLocality,
        MeshPlacementHint::SecretReconstructable,
        MeshPlacementHint::LowLatency,
    ];
    shuffled.sort();
    assert_eq!(shuffled, ASCENDING);

    for (index, left) in ASCENDING.iter().enumerate() {
        for (other_index, right) in ASCENDING.iter().enumerate() {
            let expected = index.cmp(&other_index);
            assert_eq!(
                left.cmp(right),
                expected,
                "cmp({left:?}, {right:?}) should follow declaration order",
            );
            assert_eq!(left.partial_cmp(right), Some(expected));
        }
    }
}

#[test]
fn min_and_max_follow_hint_ordering() {
    assert_eq!(
        std::cmp::min(MeshPlacementHint::LowLatency, MeshPlacementHint::AvoidDerp),
        MeshPlacementHint::LowLatency,
    );
    assert_eq!(
        std::cmp::max(
            MeshPlacementHint::DataLocality,
            MeshPlacementHint::HighResources,
        ),
        MeshPlacementHint::HighResources,
    );
}

#[test]
fn pascal_case_json_tags_are_rejected() {
    for bad_tag in [
        "DataLocality",
        "LowLatency",
        "HighResources",
        "SecretReconstructable",
        "AvoidDerp",
    ] {
        let json = format!("\"{bad_tag}\"");
        assert!(
            serde_json::from_str::<MeshPlacementHint>(&json).is_err(),
            "PascalCase tag {bad_tag} must not deserialize",
        );
    }
}
