const HYBRID_SIGNING_ROUNDTRIP_TESTS: &str =
    include_str!("../../fcp-crypto/tests/hybrid_signing_roundtrip.rs");
const FCP_CRYPTO_LIB: &str = include_str!("../../fcp-crypto/src/lib.rs");
const FCP_CRYPTO_HYBRID: &str = include_str!("../../fcp-crypto/src/hybrid.rs");
const CAPABILITY_SOURCE: &str = include_str!("../../fcp-core/src/capability.rs");
const AUDIT_SOURCE: &str = include_str!("../../fcp-core/src/audit.rs");
const OPERATION_SOURCE: &str = include_str!("../../fcp-core/src/operation.rs");
const REVOCATION_SOURCE: &str = include_str!("../../fcp-core/src/revocation.rs");
const MANIFEST_SOURCE: &str = include_str!("../../fcp-manifest/src/lib.rs");
const FCPS_SOURCE: &str = include_str!("../../fcp-protocol/src/fcps.rs");

const OBJECT_TYPES: &[&str] = &[
    "capability_token",
    "audit_event",
    "manifest",
    "gossip_frame",
    "revocation",
    "operation_receipt",
    "zone_checkpoint",
];

const REQUIRED_SUFFIXES: &[&str] = &[
    "classical_only_roundtrip",
    "pq_only_roundtrip",
    "both_sigs_roundtrip",
    "either_ok_policy_accepts_one",
    "both_required_policy_rejects_one",
];

const REQUIRED_MIGRATION_MARKERS: &[(&str, &str, &str)] = &[
    (
        "fcp-crypto public trait export",
        FCP_CRYPTO_LIB,
        "HybridSignable",
    ),
    (
        "fcp-crypto signable verifier",
        FCP_CRYPTO_HYBRID,
        "pub fn verify_signable",
    ),
    (
        "policy downgrade helper",
        FCP_CRYPTO_HYBRID,
        "pub fn downgrade_policy_to_either_ok",
    ),
    (
        "policy downgrade audit test",
        HYBRID_SIGNING_ROUNDTRIP_TESTS,
        "fn test_policy_downgrade_emits_audit()",
    ),
    (
        "capability token",
        CAPABILITY_SOURCE,
        "impl<S> HybridSignable for CapabilityToken<S>",
    ),
    (
        "capability token envelope alias",
        CAPABILITY_SOURCE,
        "pub type HybridSignedCapabilityToken",
    ),
    (
        "capability token migrated transcript",
        CAPABILITY_SOURCE,
        "fn hybrid_signing_bytes(&self)",
    ),
    (
        "capability token object kind",
        CAPABILITY_SOURCE,
        "HybridSignedObjectKind::CapabilityToken",
    ),
    (
        "audit event",
        AUDIT_SOURCE,
        "impl HybridSignable for AuditEvent",
    ),
    (
        "audit event envelope alias",
        AUDIT_SOURCE,
        "pub type HybridSignedAuditEvent",
    ),
    (
        "audit event object kind",
        AUDIT_SOURCE,
        "HybridSignedObjectKind::AuditEvent",
    ),
    (
        "zone checkpoint",
        AUDIT_SOURCE,
        "impl HybridSignable for ZoneCheckpoint",
    ),
    (
        "zone checkpoint envelope alias",
        AUDIT_SOURCE,
        "pub type HybridSignedZoneCheckpoint",
    ),
    (
        "zone checkpoint object kind",
        AUDIT_SOURCE,
        "HybridSignedObjectKind::ZoneCheckpoint",
    ),
    (
        "manifest",
        MANIFEST_SOURCE,
        "impl HybridSignable for ConnectorManifest",
    ),
    (
        "manifest envelope alias",
        MANIFEST_SOURCE,
        "pub type HybridSignedConnectorManifest",
    ),
    (
        "manifest object kind",
        MANIFEST_SOURCE,
        "HybridSignedObjectKind::Manifest",
    ),
    (
        "gossip frame payload",
        FCPS_SOURCE,
        "impl HybridSignable for SignedFcpsFramePayload",
    ),
    (
        "gossip frame object kind",
        FCPS_SOURCE,
        "HybridSignedObjectKind::GossipFrame",
    ),
    (
        "gossip frame envelope alias",
        FCPS_SOURCE,
        "pub type HybridSignedFcpsFrame",
    ),
    (
        "gossip frame hybrid constructor",
        FCPS_SOURCE,
        "pub fn new_hybrid",
    ),
    (
        "gossip frame hybrid verifier",
        FCPS_SOURCE,
        "pub fn verify_hybrid_signed_fcps_frame",
    ),
    (
        "revocation object",
        REVOCATION_SOURCE,
        "impl HybridSignable for RevocationObject",
    ),
    (
        "revocation object envelope alias",
        REVOCATION_SOURCE,
        "pub type HybridSignedRevocationObject",
    ),
    (
        "revocation event",
        REVOCATION_SOURCE,
        "impl HybridSignable for RevocationEvent",
    ),
    (
        "revocation event envelope alias",
        REVOCATION_SOURCE,
        "pub type HybridSignedRevocationEvent",
    ),
    (
        "revocation head",
        REVOCATION_SOURCE,
        "impl HybridSignable for RevocationHead",
    ),
    (
        "revocation head envelope alias",
        REVOCATION_SOURCE,
        "pub type HybridSignedRevocationHead",
    ),
    (
        "revocation object kind",
        REVOCATION_SOURCE,
        "HybridSignedObjectKind::Revocation",
    ),
    (
        "operation receipt",
        OPERATION_SOURCE,
        "impl HybridSignable for OperationReceipt",
    ),
    (
        "operation receipt envelope alias",
        OPERATION_SOURCE,
        "pub type HybridSignedOperationReceipt",
    ),
    (
        "operation receipt object kind",
        OPERATION_SOURCE,
        "HybridSignedObjectKind::OperationReceipt",
    ),
];

#[test]
fn test_every_signed_object_has_roundtrip_test() {
    for object_type in OBJECT_TYPES {
        for suffix in REQUIRED_SUFFIXES {
            let fn_name = format!("fn test_{object_type}_{suffix}()");
            assert!(
                HYBRID_SIGNING_ROUNDTRIP_TESTS.contains(&fn_name),
                "missing required hybrid signing test function {fn_name}"
            );
        }
    }
}

#[test]
fn test_every_signed_object_surface_is_hybrid_signable() {
    for (label, source, marker) in REQUIRED_MIGRATION_MARKERS {
        assert!(
            source.contains(marker),
            "missing hybrid signing migration marker for {label}: {marker}"
        );
    }
}
