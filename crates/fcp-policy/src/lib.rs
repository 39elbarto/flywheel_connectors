//! # FCP Policy
//!
//! Canonical owner of zone, capability, provenance, and approval semantics for
//! the Flywheel Connector Protocol. This crate defines the trust model, access
//! control, data flow policy, and policy evaluation engine.
//!
//! ## Semantic Domains Owned
//!
//! - **Zone model**: `ZoneId`, `ZoneDefinitionObject`, `ZoneTransportPolicy`,
//!   `ZoneKeyManifest`, `ZoneKeyRing`
//! - **Capabilities**: `CapabilityToken`, `CapabilityGrant`, `CapabilityVerifier`,
//!   `CapabilityId`, `CapabilityConstraints`
//! - **Identity & trust**: `PrincipalId`, `TailscaleNodeId`, `TrustLevel`,
//!   `SafetyTier`, `RiskLevel`
//! - **Provenance & taint**: `Provenance`, `IntegrityLevel`, `ConfidentialityLevel`,
//!   `TaintFlags`, `LabelAdjustment`, `SanitizerReceipt`
//! - **Approval workflow**: `ApprovalToken`, `ApprovalScope`, `ApprovalMode`
//! - **Policy engine**: `PolicyBundle`, `PolicyEngine`, `PolicyDecision`
//!
//! ## Migration Note
//!
//! This crate currently re-exports types from `fcp-core`. As the FCP3 migration
//! progresses, type definitions will move here and `fcp-core` will re-export from
//! this crate instead. Consumers should target `fcp_policy::` imports for new code.

#![forbid(unsafe_code)]

// ── Zone Model ─────────────────────────────────────────────────────

pub use fcp_core::{ZoneId, ZoneIdError, ZoneIdHash};

pub use fcp_core::{TransportMode, ZoneDefinitionObject, ZonePolicyObject, ZoneTransportPolicy};

// ── Zone Keys ──────────────────────────────────────────────────────

pub use fcp_core::{
    RekeyPolicy, WrappedZoneKey, ZoneKey, ZoneKeyAlgorithm, ZoneKeyError, ZoneKeyId,
    ZoneKeyManifest, ZoneKeyRing,
};

// ── Capability Tokens & Grants ─────────────────────────────────────

pub use fcp_core::{
    CapabilityConstraintEvaluator, CapabilityConstraints, CapabilityGrant, CapabilityId,
    CapabilityObject, CapabilityToken, CapabilityVerifier, RoleAssignment, RoleObject,
};

// ── Capability-Token Typestate Ladder ─────────────────────────────
//
// Exposes the phantom-type markers so consumers can write
// `fcp_policy::CapabilityToken<ConstraintsEnforced>` in their dispatch
// signatures without importing fcp-core directly.

pub use fcp_core::{AnyVerified, BoundVerified, ConstraintsEnforced, UnboundVerified, Unverified};

// ── Identity & Trust ───────────────────────────────────────────────

pub use fcp_core::{Principal, PrincipalId, SafetyTier, TailscaleNodeId, TaintLevel, TrustLevel};

// ── Operational Model Selection ───────────────────────────────────

/// Operational model version requested by truth-resolution policy.
///
/// This is the policy-side mirror of fcp-host's runtime
/// `DeploymentMode`: the policy says what model an operator requested,
/// while the host deployment classifier says what the current topology
/// can safely support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OperationalModelVersion {
    /// V1 host-first operation. Safe fallback for single-host deployments.
    V1HostFirst,
    /// V2 mesh-native operation. Requires an active mesh unless explicitly
    /// accepted as degraded single-host mode.
    V2MeshNative,
}

impl OperationalModelVersion {
    /// Stable label for logs and policy diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V1HostFirst => "V1-host-first",
            Self::V2MeshNative => "V2-mesh-native",
        }
    }
}

/// Environment variable controlling the default truth-precedence model.
pub const TRUTH_PRECEDENCE_DEFAULT_ENV: &str = "FCP_TRUTH_PRECEDENCE_DEFAULT";

/// Environment variable that explicitly accepts degraded V2 on single-host
/// deployments. It is only honored when `FCP_TRUTH_PRECEDENCE_DEFAULT`
/// explicitly requests V2.
pub const TRUTH_PRECEDENCE_ACCEPT_DEGRADED_SINGLE_HOST_ENV: &str =
    "FCP_TRUTH_PRECEDENCE_ACCEPT_DEGRADED_SINGLE_HOST";

/// Stable operator warning emitted when V2 defaults are detected on a
/// single-host deployment without the explicit degraded-mode opt-in.
pub const SINGLE_HOST_V2_FALLBACK_WARNING: &str = "WARN: V2MeshNative requested on a single-host deployment without explicit degraded-mode opt-in; falling back to V1HostFirst.";

/// Resolved operational model after deployment-topology guardrails are applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationalModelSelection {
    /// Model requested by env/config/defaults before topology guardrails.
    pub requested: OperationalModelVersion,
    /// Model that callers should actually use.
    pub effective: OperationalModelVersion,
    /// Whether the topology check detected a single-host deployment.
    pub single_host_detected: bool,
    /// Whether degraded V2 was explicitly accepted.
    pub degraded_v2_opt_in: bool,
    /// Operator-visible warning to log, if a fallback was applied.
    pub warning: Option<&'static str>,
}

/// Return true when the raw env value requests legacy V1 host-first mode.
#[must_use]
pub fn truth_precedence_env_requests_v1(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "v1" | "v1-host-first" | "v1_host_first" | "host-first" | "host_first"
        )
    })
}

/// Return true when the raw env value explicitly requests V2 mesh-native mode.
#[must_use]
pub fn truth_precedence_env_requests_v2(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "v2" | "v2-mesh-native" | "v2_mesh_native" | "mesh-native" | "mesh_native"
        )
    })
}

/// Return true when the raw env value accepts degraded V2 single-host mode.
#[must_use]
pub fn truth_precedence_accepts_degraded_single_host(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "accept" | "accept-degraded" | "accept_degraded"
        )
    })
}

/// Resolve the requested operational model from a raw env value.
///
/// Unset or unknown values retain the post-cutover V2 request, matching the
/// br-4la3k default before topology guardrails are applied.
#[must_use]
pub fn requested_operational_model_from_env(raw: Option<&str>) -> OperationalModelVersion {
    if truth_precedence_env_requests_v1(raw) {
        OperationalModelVersion::V1HostFirst
    } else {
        OperationalModelVersion::V2MeshNative
    }
}

/// Apply single-host topology guardrails to the requested operational model.
///
/// V2 remains available on a single-host deployment only when the operator both
/// explicitly requests V2 and explicitly accepts degraded single-host mode. The
/// default V2 request, or an explicit V2 request without the accept flag, falls
/// back to V1 with a stable warning.
#[must_use]
pub fn select_operational_model_for_deployment(
    requested: OperationalModelVersion,
    explicit_v2_requested: bool,
    degraded_v2_accepted: bool,
    single_host_detected: bool,
) -> OperationalModelSelection {
    let degraded_v2_opt_in = single_host_detected
        && requested == OperationalModelVersion::V2MeshNative
        && explicit_v2_requested
        && degraded_v2_accepted;
    let should_fallback = single_host_detected
        && requested == OperationalModelVersion::V2MeshNative
        && !degraded_v2_opt_in;

    OperationalModelSelection {
        requested,
        effective: if should_fallback {
            OperationalModelVersion::V1HostFirst
        } else {
            requested
        },
        single_host_detected,
        degraded_v2_opt_in,
        warning: should_fallback.then_some(SINGLE_HOST_V2_FALLBACK_WARNING),
    }
}

/// Resolve the effective operational model from raw env values plus topology.
#[must_use]
pub fn select_operational_model_from_env_for_deployment(
    default_env: Option<&str>,
    accept_degraded_env: Option<&str>,
    single_host_detected: bool,
) -> OperationalModelSelection {
    select_operational_model_for_deployment(
        requested_operational_model_from_env(default_env),
        truth_precedence_env_requests_v2(default_env),
        truth_precedence_accepts_degraded_single_host(accept_degraded_env),
        single_host_detected,
    )
}

// ── Provenance & Taint Tracking ────────────────────────────────────

pub use fcp_core::{
    AdjustmentKind, ConfidentialityLevel, FlowCheckResult, IntegrityLevel, LabelAdjustment,
    Provenance, ProvenanceRecord, ProvenanceStep, ProvenanceViolation, TaintFlag, TaintFlags,
    TaintReduction, ZoneCrossing,
};

// ── Approval Workflow ──────────────────────────────────────────────

pub use fcp_core::{
    ApprovalMode, ApprovalScope, ApprovalToken, DeclassificationScope, ElevationScope,
    ExecutionScope, InputConstraint, SanitizerReceipt, TaintDecision,
};

// ── Policy Engine & Evaluation ─────────────────────────────────────

pub use fcp_core::{
    DecisionReasonCode, DecisionReceiptPolicy, PolicyBundle, PolicyBundleBuilder,
    PolicyBundleError, PolicyBundleObject, PolicyBundlePolicyRef, PolicyBundleResolved,
    PolicyBundleSignature, PolicyDecision, PolicyEngine, PolicyPattern,
};

// ── Policy Diffs ───────────────────────────────────────────────────

pub use fcp_core::{
    CapabilityDiff, PolicyBundleDiff, PolicyChangedFields, PolicyDiffError, PolicyListDiff,
    PolicyRiskCode, PolicyRiskFlag, PolicyRiskSeverity, PolicyRiskSummary, ResourceDiff, RoleDiff,
    TransportPolicyChange, ZoneDefinitionDiff, ZonePolicyDiff,
};

// ── Resource Objects ───────────────────────────────────────────────

pub use fcp_core::ResourceObject;

// ── Risk Level (operation classification) ──────────────────────────

pub use fcp_core::RiskLevel;

// ── Enforcement Ordering ─────────────────────────────────────────────

pub use fcp_core::{
    CheckOutcome, CheckRecord, EnforcementCheckId, EnforcementCheckOrder, EnforcementDecision,
};

// ── Posture & Device Admission ──────────────────────────────────────

pub use fcp_core::{
    PostureAttestation, PostureAttributeKey, PostureAttributeValue, PostureCheckResult,
    PostureRequirement, PostureRequirements, PostureRequirementsBuilder,
};

// ── Device Enrollment ───────────────────────────────────────────────

pub use fcp_core::{
    DeviceEnrollmentApproval, DeviceEnrollmentRequest, DeviceId, DeviceMetadata, EnrollmentStatus,
    KeyRotationSchedule, KeyType, NodeKeyAttestation,
};

// ── Post-Compromise Security (PCS) ──────────────────────────────────

pub use fcp_core::pcs;

// ── Shared Identity Types ──────────────────────────────────────────

pub use fcp_core::{ConnectorId, InstanceId, ObjectId, OperationId};

// ── Capability Constraint Enforcement (m8j0q.A.1) ─────────────────

pub mod constraint_enforcer;

pub use constraint_enforcer::{
    CapabilityConstraintEnforcer, ConstraintDenialKind, ConstraintDenialReason,
    ConstraintEvaluation, DefaultConstraintEnforcer, RequestDescriptor,
};

// ── Constraint Enforcement Receipts (m8j0q.A.7) ───────────────────
//
// Re-exported from fcp-evidence (canonical home) so consumers can write
// `fcp_policy::ConstraintEnforcementReceipt` without importing both crates.

pub use fcp_evidence::{
    ConstraintEnforcementReceipt, ConstraintsEvaluatedSummary, EvaluationOutcomeRecord,
    ReceiptBody, ReceiptError, ReceiptId, RequestDescriptorHash,
};

// ── Revocation Cascade (m8j0q.A.9) ────────────────────────────────
//
// Re-exported from fcp-evidence (canonical home).

pub use fcp_evidence::{
    AttestationChain, CascadeConfig, CascadeHop, CascadeReceipt, CascadeRejection,
    RevocationRecord, check_revocation_chain,
};

// ── Lattice-Trapdoor Capability Delegation (kyopb.1.3, V4 PQ) ─────
//
// Stub trait surface for post-quantum-safe capability delegation via
// lattice trapdoors. The full design is documented in
// `docs/post-quantum/lattice_trapdoor_delegation.md`. The cryptographic
// primitives live in a future `fcp-crypto-pq` crate (kyopb.1.3.1).

pub mod lattice_delegation;

pub use lattice_delegation::{
    DelegationCertificate, DelegationCertificateId, DelegationPeriod, LatticeDelegationError,
    LatticeDelegationVerifier, LatticeDelegationVerifierImpl, LatticeSubToken,
    LatticeVerificationReceipt, UnimplementedLatticeDelegationVerifier,
};

// ── Error Types ────────────────────────────────────────────────────

pub use fcp_core::{FcpError, FcpResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_exports_zone_types() {
        let z = ZoneId::work();
        assert_eq!(z.as_str(), ZoneId::WORK);
    }

    #[test]
    fn policy_exports_capability_types() {
        let cap = CapabilityId::from_static("gmail.read");
        assert_eq!(cap.as_str(), "gmail.read");
    }

    #[test]
    fn policy_exports_identity_types() {
        let _: TrustLevel = TrustLevel::Owner;
        let _: SafetyTier = SafetyTier::Safe;
        let _: SafetyTier = SafetyTier::Risky;
        let _: SafetyTier = SafetyTier::Dangerous;
    }

    #[test]
    fn single_host_v2_default_falls_back_to_v1_without_opt_in() {
        let selection = select_operational_model_from_env_for_deployment(None, None, true);

        assert_eq!(selection.requested, OperationalModelVersion::V2MeshNative);
        assert_eq!(selection.effective, OperationalModelVersion::V1HostFirst);
        assert!(selection.single_host_detected);
        assert!(!selection.degraded_v2_opt_in);
        assert_eq!(selection.warning, Some(SINGLE_HOST_V2_FALLBACK_WARNING));
    }

    #[test]
    fn single_host_v2_explicit_request_still_falls_back_without_accept_flag() {
        let selection = select_operational_model_from_env_for_deployment(Some("v2"), None, true);

        assert_eq!(selection.requested, OperationalModelVersion::V2MeshNative);
        assert_eq!(selection.effective, OperationalModelVersion::V1HostFirst);
        assert_eq!(selection.warning, Some(SINGLE_HOST_V2_FALLBACK_WARNING));
    }

    #[test]
    fn single_host_v2_explicit_request_with_accept_flag_keeps_v2() {
        let selection = select_operational_model_from_env_for_deployment(
            Some("v2-mesh-native"),
            Some("accept-degraded"),
            true,
        );

        assert_eq!(selection.requested, OperationalModelVersion::V2MeshNative);
        assert_eq!(selection.effective, OperationalModelVersion::V2MeshNative);
        assert!(selection.degraded_v2_opt_in);
        assert_eq!(selection.warning, None);
    }

    #[test]
    fn single_host_v2_non_single_host_keeps_default_v2() {
        let selection = select_operational_model_from_env_for_deployment(None, None, false);

        assert_eq!(selection.requested, OperationalModelVersion::V2MeshNative);
        assert_eq!(selection.effective, OperationalModelVersion::V2MeshNative);
        assert!(!selection.single_host_detected);
        assert_eq!(selection.warning, None);
    }

    #[test]
    fn single_host_v2_v1_env_stays_v1() {
        let selection =
            select_operational_model_from_env_for_deployment(Some("host-first"), None, true);

        assert_eq!(selection.requested, OperationalModelVersion::V1HostFirst);
        assert_eq!(selection.effective, OperationalModelVersion::V1HostFirst);
        assert_eq!(selection.warning, None);
    }

    #[test]
    fn policy_exports_provenance_types() {
        let _: IntegrityLevel = IntegrityLevel::Owner;
        let _: ConfidentialityLevel = ConfidentialityLevel::Public;
        let _: TaintFlag = TaintFlag::PublicInput;
    }

    #[test]
    fn policy_exports_approval_types() {
        fn _scope_exists(_s: ApprovalScope) {}

        let _: ApprovalMode = ApprovalMode::Interactive;
        // ApprovalScope variants carry data — just verify the type exists
        let _ = _scope_exists;
    }

    #[test]
    fn policy_exports_risk_types() {
        let _: RiskLevel = RiskLevel::Low;
        let _: RiskLevel = RiskLevel::High;
    }

    #[test]
    fn policy_exports_policy_engine_types() {
        fn _engine_exists(_engine: PolicyEngine) {}
        let _ = _engine_exists;
        let decision = PolicyDecision::deny(DecisionReasonCode::CapabilityInsufficient, Vec::new());
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::CapabilityInsufficient
        );
    }

    #[test]
    fn policy_exports_zone_key_types() {
        let _: ZoneKeyAlgorithm = ZoneKeyAlgorithm::ChaCha20Poly1305;
    }

    #[test]
    fn policy_exports_enforcement_types() {
        let order = EnforcementCheckOrder::canonical_order();
        assert_eq!(order.len(), EnforcementCheckOrder::COUNT);
        let _: CheckOutcome = CheckOutcome::Allow;
    }

    #[test]
    fn policy_exports_posture_types() {
        fn _posture_exists(_a: PostureAttestation, _r: PostureRequirements) {}
    }

    #[test]
    fn policy_exports_enrollment_types() {
        let _: EnrollmentStatus = EnrollmentStatus::Approved;
        let _: KeyType = KeyType::Signing;
        let device = DeviceId::new("test-device");
        assert_eq!(device.as_str(), "test-device");
    }

    #[test]
    fn policy_exports_pcs_module() {
        let _: pcs::PcsMode = pcs::PcsMode::Disabled;
    }
}
