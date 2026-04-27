//! Control-plane retention classification conformance.
//!
//! `fcp_protocol::retention_for_schema` is the NORMATIVE classifier
//! that decides whether a control-plane object MUST be stored for
//! audit (`Required`) or MAY be dropped after processing
//! (`Ephemeral`). Storage operators rely on this single function to
//! determine durability obligations across every protocol message
//! that crosses FCPC.
//!
//! Documented invariants (from
//! `fcp-protocol/src/control_plane.rs::retention_for_schema`):
//!
//! 1. Explicit Required prefixes (audit-critical): `fcp.invoke`,
//!    `fcp.receipt`, `fcp.approval`, `fcp.secret`, `fcp.revoke`,
//!    `fcp.audit`, `fcp.grant`, `fcp.membership`.
//! 2. Explicit Ephemeral prefixes (drop-after-processing):
//!    `fcp.health`, `fcp.handshake`, `fcp.status`, `fcp.introspect`,
//!    `fcp.configure`, `fcp.simulate`, `fcp.ping`, `fcp.heartbeat`.
//! 3. UNKNOWN schemas default to `Required` (fail-safe toward
//!    auditability — so a connector that publishes a new schema
//!    without updating the classifier still gets stored).
//! 4. `namespace_matches_prefix` uses DOT-delimited semantics:
//!    `fcp.heartbeat-evil` MUST NOT match `fcp.heartbeat`. Otherwise
//!    a malicious or accidentally-shaped namespace would slip out
//!    of audit retention.
//! 5. Sub-namespace inheritance: `fcp.heartbeat.v2` DOES match the
//!    `fcp.heartbeat` prefix (legitimate nested versioning).
//! 6. Required-prefix check runs BEFORE Ephemeral-prefix check —
//!    if a schema somehow appeared in BOTH lists (it shouldn't),
//!    Required would win.

use fcp_cbor::SchemaId;
use fcp_protocol::{ControlPlaneRetention, requires_storage, retention_for_schema};
use semver::Version;

fn schema(namespace: &str, name: &str) -> SchemaId {
    SchemaId::new(namespace, name, Version::new(1, 0, 0))
}

#[test]
fn invoke_namespace_classifies_as_required() {
    let s = schema("fcp.invoke", "InvokeRequest");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Required);
    assert!(requires_storage(&s));
}

#[test]
fn receipt_namespace_classifies_as_required() {
    let s = schema("fcp.receipt", "OperationReceipt");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Required);
}

#[test]
fn approval_namespace_classifies_as_required() {
    let s = schema("fcp.approval", "ApprovalGrant");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Required);
}

#[test]
fn audit_namespace_classifies_as_required() {
    let s = schema("fcp.audit", "AuditHead");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Required);
}

#[test]
fn revocation_namespace_classifies_as_required() {
    // Revocations MUST be stored — without them, an attacker who
    // captures a revoked capability could replay it forever.
    let s = schema("fcp.revoke", "Revocation");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Required);
}

#[test]
fn health_namespace_classifies_as_ephemeral() {
    let s = schema("fcp.health", "HealthCheck");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Ephemeral);
    assert!(!requires_storage(&s));
}

#[test]
fn heartbeat_namespace_classifies_as_ephemeral() {
    let s = schema("fcp.heartbeat", "Heartbeat");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Ephemeral);
}

#[test]
fn handshake_namespace_classifies_as_ephemeral() {
    let s = schema("fcp.handshake", "HandshakeRequest");
    assert_eq!(retention_for_schema(&s), ControlPlaneRetention::Ephemeral);
}

#[test]
fn unknown_namespace_defaults_to_required_failsafe() {
    // Failsafe: a connector that publishes a new schema before the
    // classifier knows about it MUST still be stored. Otherwise a
    // forgotten classifier update would silently drop audit data.
    let s = schema("fcp.something_brand_new", "NovelObject");
    assert_eq!(
        retention_for_schema(&s),
        ControlPlaneRetention::Required,
        "unknown namespace MUST default to Required (audit-failsafe)"
    );

    let s2 = schema("not.fcp.at.all", "ThirdPartyObject");
    assert_eq!(
        retention_for_schema(&s2),
        ControlPlaneRetention::Required,
        "non-fcp namespace MUST also default to Required"
    );
}

#[test]
fn pathological_namespace_does_not_match_ephemeral_prefix() {
    // The dot-delimited matcher prevents `fcp.heartbeat-evil` from
    // sneaking out of audit retention by mimicking the
    // `fcp.heartbeat` prefix.
    let s = schema("fcp.heartbeat-evil", "ImpostorHeartbeat");
    assert_eq!(
        retention_for_schema(&s),
        ControlPlaneRetention::Required,
        "pathological 'fcp.heartbeat-evil' MUST NOT match the 'fcp.heartbeat' Ephemeral \
         prefix; it must default to Required for safety"
    );

    // Same defense for "-required" suffixes against Required prefixes.
    // A sneaky attacker can't bypass Required either by appending '-' —
    // but the safer default catches it: it falls through to Required
    // anyway, so this just double-checks the dot-discipline.
    let s2 = schema("fcp.invokeXXX", "FakeInvoke");
    assert_eq!(
        retention_for_schema(&s2),
        ControlPlaneRetention::Required,
        "pathological 'fcp.invokeXXX' falls through to default Required"
    );
}

#[test]
fn legitimate_subnamespace_inherits_parent_retention() {
    // The dot-delimited matcher MUST accept legitimate nested
    // versioning like `fcp.heartbeat.v2`.
    let ephemeral_sub = schema("fcp.heartbeat.v2", "HeartbeatV2");
    assert_eq!(
        retention_for_schema(&ephemeral_sub),
        ControlPlaneRetention::Ephemeral,
        "legitimate sub-namespace 'fcp.heartbeat.v2' MUST inherit Ephemeral retention"
    );

    let required_sub = schema("fcp.audit.v3", "AuditV3");
    assert_eq!(
        retention_for_schema(&required_sub),
        ControlPlaneRetention::Required,
        "legitimate sub-namespace 'fcp.audit.v3' MUST inherit Required retention"
    );
}

#[test]
fn classification_is_independent_of_schema_name_and_version() {
    // Only the namespace is consulted by the classifier. Different
    // names and versions under the same namespace MUST produce the
    // same retention.
    let names = ["A", "B", "VeryLongName", ""];
    let versions = [
        Version::new(0, 0, 0),
        Version::new(1, 0, 0),
        Version::new(99, 99, 99),
    ];
    for name in &names {
        for v in &versions {
            let s = SchemaId::new("fcp.heartbeat", *name, v.clone());
            assert_eq!(
                retention_for_schema(&s),
                ControlPlaneRetention::Ephemeral,
                "name='{name}' version={v} under fcp.heartbeat must remain Ephemeral"
            );
        }
    }
}

#[test]
fn requires_storage_is_consistent_with_retention_for_schema() {
    // The `requires_storage` convenience must agree with
    // retention_for_schema for every namespace we test. Otherwise
    // callers using one helper would diverge from those using the
    // other.
    for ns in [
        "fcp.invoke",
        "fcp.receipt",
        "fcp.approval",
        "fcp.secret",
        "fcp.revoke",
        "fcp.audit",
        "fcp.grant",
        "fcp.membership",
        "fcp.health",
        "fcp.handshake",
        "fcp.status",
        "fcp.introspect",
        "fcp.configure",
        "fcp.simulate",
        "fcp.ping",
        "fcp.heartbeat",
        "fcp.unknown_future_schema",
        "third.party.namespace",
    ] {
        let s = schema(ns, "Anything");
        let direct = retention_for_schema(&s) == ControlPlaneRetention::Required;
        assert_eq!(
            requires_storage(&s),
            direct,
            "requires_storage and retention_for_schema disagree for ns={ns}"
        );
    }
}

#[test]
fn empty_namespace_defaults_to_required() {
    // Edge case: empty namespace cannot match any prefix; must
    // default to Required.
    let s = schema("", "Empty");
    assert_eq!(
        retention_for_schema(&s),
        ControlPlaneRetention::Required,
        "empty namespace must default to Required"
    );
}
