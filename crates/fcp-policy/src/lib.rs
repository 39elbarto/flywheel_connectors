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
    CapabilityConstraints, CapabilityGrant, CapabilityId, CapabilityObject, CapabilityToken,
    CapabilityVerifier, RoleAssignment, RoleObject,
};

// ── Identity & Trust ───────────────────────────────────────────────

pub use fcp_core::{Principal, PrincipalId, SafetyTier, TailscaleNodeId, TaintLevel, TrustLevel};

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
    DecisionReceiptPolicy, PolicyBundle, PolicyBundleBuilder, PolicyBundleError,
    PolicyBundleObject, PolicyBundlePolicyRef, PolicyBundleResolved, PolicyBundleSignature,
    PolicyDecision, PolicyEngine, PolicyPattern,
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

pub use fcp_core::{ConnectorId, InstanceId, OperationId};

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
        let decision = PolicyDecision::deny(
            fcp_core::DecisionReasonCode::CapabilityInsufficient,
            Vec::new(),
        );
        assert_eq!(decision.decision, fcp_core::Decision::Deny);
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
        fn _posture_exists(
            _a: PostureAttestation,
            _r: PostureRequirements,
        ) {}
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
