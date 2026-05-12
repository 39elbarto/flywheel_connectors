const ROUNDTRIP_SOURCE: &str = include_str!("../../fcp-crypto/tests/hybrid_signing_roundtrip.rs");

const OBJECT_TYPES: [&str; 7] = [
    "capability_token",
    "audit_event",
    "manifest",
    "gossip_frame",
    "revocation",
    "operation_receipt",
    "zone_checkpoint",
];

const REQUIRED_CASES: [&str; 5] = [
    "classical_only_roundtrip",
    "pq_only_roundtrip",
    "both_sigs_roundtrip",
    "either_ok_policy_accepts_one",
    "both_required_policy_rejects_one",
];

#[test]
fn hybrid_signing_roundtrip_suite_names_all_required_cases() {
    let mut missing = Vec::new();
    for object_type in OBJECT_TYPES {
        for required_case in REQUIRED_CASES {
            let test_name = format!("{object_type}_{required_case}");
            if !ROUNDTRIP_SOURCE.contains(&test_name) {
                missing.push(test_name);
            }
        }
    }

    assert!(
        missing.is_empty(),
        "hybrid signing roundtrip suite is missing required tests: {missing:?}"
    );
}
