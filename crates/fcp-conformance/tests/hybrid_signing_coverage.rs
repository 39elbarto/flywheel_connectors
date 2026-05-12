const ROUNDTRIP_SOURCE: &str = include_str!("../../fcp-crypto/tests/hybrid_signing_roundtrip.rs");

use fcp_core::{
    AuditEvent, CapabilityToken, HybridSignedAuditEvent, HybridSignedCapabilityToken,
    HybridSignedOperationReceipt, HybridSignedRevocationEvent, HybridSignedRevocationHead,
    HybridSignedRevocationObject, HybridSignedZoneCheckpoint, OperationReceipt, RevocationEvent,
    RevocationHead, RevocationObject, ZoneCheckpoint,
};
use fcp_crypto::{
    CryptoResult, Ed25519VerifyingKey, HybridSignable, HybridSignedObjectKind, HybridVerifyReport,
    MlDsa65VerifyingKey, SignedEnvelope, signing_bytes_for_canonical_payload,
};
use fcp_manifest::{ConnectorManifest, HybridSignedConnectorManifest};
use fcp_protocol::{
    HybridSignedFcpsFrame, SignedFcpsFramePayload, verify_hybrid_signed_fcps_frame,
};

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

#[test]
fn hybrid_signing_roundtrip_suite_covers_policy_downgrade_audit() {
    assert!(
        ROUNDTRIP_SOURCE.contains("test_policy_downgrade_emits_audit"),
        "hybrid signing suite must cover operator-authorized policy downgrade audit"
    );
}

type HybridFrameVerifyFn = fn(
    &HybridSignedFcpsFrame,
    &Ed25519VerifyingKey,
    &MlDsa65VerifyingKey,
) -> CryptoResult<HybridVerifyReport>;

const fn assert_hybrid_signable<T: HybridSignable>() {}

fn assert_envelope_alias<T: HybridSignable>(_alias: Option<SignedEnvelope<T>>) {}

const fn assert_hybrid_frame_verify_fn(_verify: HybridFrameVerifyFn) {}

#[test]
fn hybrid_signing_real_object_families_are_migrated() {
    assert_hybrid_signable::<CapabilityToken>();
    assert_hybrid_signable::<AuditEvent>();
    assert_hybrid_signable::<ConnectorManifest>();
    assert_hybrid_signable::<SignedFcpsFramePayload>();
    assert_hybrid_signable::<RevocationObject>();
    assert_hybrid_signable::<RevocationEvent>();
    assert_hybrid_signable::<RevocationHead>();
    assert_hybrid_signable::<OperationReceipt>();
    assert_hybrid_signable::<ZoneCheckpoint>();

    assert_eq!(
        <CapabilityToken as HybridSignable>::OBJECT_KIND,
        HybridSignedObjectKind::CapabilityToken
    );
    assert_eq!(
        <AuditEvent as HybridSignable>::OBJECT_KIND,
        HybridSignedObjectKind::AuditEvent
    );
    assert_eq!(
        <ConnectorManifest as HybridSignable>::OBJECT_KIND,
        HybridSignedObjectKind::Manifest
    );
    assert_eq!(
        <SignedFcpsFramePayload as HybridSignable>::OBJECT_KIND,
        HybridSignedObjectKind::GossipFrame
    );
    assert_eq!(
        <OperationReceipt as HybridSignable>::OBJECT_KIND,
        HybridSignedObjectKind::OperationReceipt
    );
    assert_eq!(
        <ZoneCheckpoint as HybridSignable>::OBJECT_KIND,
        HybridSignedObjectKind::ZoneCheckpoint
    );
}

#[test]
fn hybrid_signing_public_aliases_cover_call_site_families() {
    assert_envelope_alias::<CapabilityToken>(None::<HybridSignedCapabilityToken>);
    assert_envelope_alias::<AuditEvent>(None::<HybridSignedAuditEvent>);
    assert_envelope_alias::<ConnectorManifest>(None::<HybridSignedConnectorManifest>);
    assert_envelope_alias::<SignedFcpsFramePayload>(None::<HybridSignedFcpsFrame>);
    assert_envelope_alias::<RevocationObject>(None::<HybridSignedRevocationObject>);
    assert_envelope_alias::<RevocationEvent>(None::<HybridSignedRevocationEvent>);
    assert_envelope_alias::<RevocationHead>(None::<HybridSignedRevocationHead>);
    assert_envelope_alias::<OperationReceipt>(None::<HybridSignedOperationReceipt>);
    assert_envelope_alias::<ZoneCheckpoint>(None::<HybridSignedZoneCheckpoint>);
}

#[test]
fn hybrid_signing_protocol_helpers_remain_public() {
    assert_hybrid_frame_verify_fn(verify_hybrid_signed_fcps_frame);

    let signing_bytes =
        signing_bytes_for_canonical_payload(HybridSignedObjectKind::Manifest, b"manifest");
    assert!(signing_bytes.starts_with(fcp_crypto::canonicalize::SIGNING_DOMAIN));
}
