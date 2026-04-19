//! # FCP Evidence
//!
//! Canonical owner of receipts, audit chain, checkpoints, and revocation
//! semantics for the Flywheel Connector Protocol. This crate defines the
//! tamper-evident structures that prove operations happened, track state
//! across epochs, and enforce key/token invalidation.
//!
//! ## Semantic Domains Owned
//!
//! - **Operation receipts**: `OperationReceipt`, `OperationIntent`, `IntentStatus`
//! - **Audit chain**: `AuditEvent`, `AuditChainHead`, `AuditChainEntry`
//! - **Checkpoints**: `ZoneCheckpoint`, `ComputationCheckpoint`, `CheckpointTrigger`
//! - **Revocation**: `RevocationObject`, `RevocationScope`, `RevocationFreshness`
//! - **Supply chain**: `SupplyChainAttestation`, `SoftwareBillOfMaterials`,
//!   `VerificationPipeline`, `VerificationEvidence`, `VerificationStep`,
//!   `VerificationDecision`, `VerificationReasonCode`
//!
//! ## Migration Note
//!
//! This crate currently re-exports types from `fcp-core`. As the FCP3 migration
//! progresses, type definitions will move here and `fcp-core` will re-export from
//! this crate instead.

#![forbid(unsafe_code)]

// ── Audit Chain ────────────────────────────────────────────────────

pub use fcp_core::{AuditEvent, AuditHead};

// ── Revocation ─────────────────────────────────────────────────────

pub use fcp_core::{
    RevocationCheckResult, RevocationEvent, RevocationHead, RevocationObject, RevocationRegistry,
    RevocationScope,
};

// ── Operation Receipts ─────────────────────────────────────────────

pub use fcp_core::{IdempotencyEntry, IntentStatus, OperationIntent, OperationReceipt};

// ── Checkpoints ────────────────────────────────────────────────────

pub use fcp_core::{
    CheckpointAdvanceState, CheckpointChunkError, CheckpointProposal, CheckpointTransferEncoding,
    CheckpointTrigger, CheckpointValidationError, ChunkedCheckpoint, ForkDetectionResult,
    ForkEvidence, FreshnessResult, MigrationCapabilityContext, ZoneCheckpoint,
};

// ── Supply Chain Attestation & Verification ────────────────────────

pub use fcp_core::{
    AttestationMaterial, AttestationMetadata, HashAlgorithm, SbomFormat, SoftwareBillOfMaterials,
    SupplyChainAttestation, SupplyChainSignature, SupplyChainVerificationPolicy, TrustRootBinding,
    VerificationDecision, VerificationEvidence, VerificationPipeline, VerificationReasonCode,
    VerificationStep,
};

// ── Content-Addressed Objects ────────────────────────────────────────

pub use fcp_core::{
    DeviceSelector, ObjectHeader, ObjectId, ObjectIdKey, ObjectIdParseError, ObjectPlacementPolicy,
    RetentionClass, StorageMeta, StoredObject,
};

// ── Shared Identity Types ──────────────────────────────────────────

pub use fcp_core::{ConnectorId, OperationId, ZoneId};

// ── Error Types ────────────────────────────────────────────────────

pub use fcp_core::{FcpError, FcpResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_exports_audit_types() {
        // Verify AuditEvent and AuditHead are accessible
        fn _audit_exists(_e: AuditEvent, _h: AuditHead) {}
    }

    #[test]
    fn evidence_exports_revocation_types() {
        let _: RevocationScope = RevocationScope::Capability;
    }

    #[test]
    fn evidence_exports_idempotency_types() {
        let _: IntentStatus = IntentStatus::Pending;
    }

    #[test]
    fn evidence_exports_checkpoint_types() {
        // CheckpointAdvanceState has struct variants — verify it compiles
        fn _state_exists(_s: CheckpointAdvanceState) {}
    }

    #[test]
    fn evidence_exports_supply_chain_types() {
        fn _sc_exists(_a: SupplyChainAttestation) {}
    }

    #[test]
    fn evidence_exports_supply_chain_verification_types() {
        fn _verify_exists(
            _decision: VerificationDecision,
            _reason: VerificationReasonCode,
            _evidence: VerificationEvidence,
            _step: VerificationStep,
            _pipeline: VerificationPipeline,
            _sbom: SoftwareBillOfMaterials,
        ) {
        }
    }

    #[test]
    fn evidence_exports_object_types() {
        let id = ObjectId::from_bytes([0_u8; 32]);
        assert_eq!(id.as_bytes(), &[0_u8; 32]);
        let _: RetentionClass = RetentionClass::Ephemeral;
    }
}
