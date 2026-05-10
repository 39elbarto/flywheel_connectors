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

pub use fcp_core::{AuditEvent, AuditHead, DecisionReceipt};

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

// ── Constraint Enforcement Receipts (m8j0q.A.7) ────────────────────

pub mod constraint_receipt;

pub use constraint_receipt::{
    ConstraintEnforcementReceipt, ConstraintReceiptVerifier, ConstraintsEvaluatedSummary,
    DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS, EvaluationOutcomeRecord, RECEIPT_ID_DOMAIN,
    RECEIPT_SIGNING_DOMAIN, ReceiptBody, ReceiptError, ReceiptId, ReceiptNonce,
    ReceiptVerificationContext, RequestDescriptorHash,
};

// ── V3/V4 Compatibility Ledger (kyopb.1.4.1) ──────────────────────

pub mod compatibility_ledger;

pub use compatibility_ledger::{
    COMPATIBILITY_LEDGER_ROOT_DOMAIN, COMPATIBILITY_LEDGER_SIGNATURE_DOMAIN,
    COMPATIBILITY_LEDGER_VERSION, CompatibilityLedgerBody, CompatibilityLedgerError,
    CompatibilityLedgerRoot, CompatibilityLedgerSignatures, CompatibilityLedgerTrustAnchors,
    CompatibilityPolicy, EntryEvidence, EntryState, KemSuite, LedgerEd25519Signature,
    LedgerMlDsa65Signature, MeshCompatibilityLedger, MigrationPhase, MlDsa65LedgerVerifier,
    NodeCompatibilityEntry, NodeFallbackPolicy, NodeTombstone, ProtocolVersion, SignatureSuite,
};

// ── Revocation Cascade (m8j0q.A.9) ─────────────────────────────────

pub mod revocation_cascade;

pub use revocation_cascade::{
    AttestationChain, CascadeConfig, CascadeHop, CascadeReceipt, CascadeRejection,
    RevocationRecord, check_revocation_chain,
};

// ── Owner-Key Migration Verification (kyopb.1.1.1) ─────────────────

pub mod owner_migration_verifier;

pub use owner_migration_verifier::{
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes,
    MlDsa65SignatureVerifier, MlDsa65VerifyingKeyBytes, OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA,
    OWNER_KEY_MIGRATION_DOMAIN, OwnerKeyMigrationAttestation, OwnerKeyMigrationTranscript,
    OwnerMigrationResult, OwnerMigrationVerificationContext, OwnerMigrationVerificationError,
    OwnerMigrationVerificationReceipt, TrustedV3OwnerMap, verify_owner_key_migration_attestation,
};

// ── Hybrid Owner-Governed Objects (kyopb.1.1.4) ───────────────────

pub mod hybrid_owner_objects;

pub use hybrid_owner_objects::{
    FcpCryptoMlDsa65Verifier, HYBRID_OWNER_OBJECT_DOMAIN, HYBRID_OWNER_OBJECT_SCHEMA,
    HybridOwnerObjectKind, HybridOwnerObjectSignatures, HybridOwnerObjectTranscript,
    HybridOwnerObjectVerificationError, HybridOwnerObjectVerificationReceipt,
    verify_hybrid_owner_object,
};

// ── Proof Graph Schema (b88ec.1) ──────────────────────────────────

pub mod proof_graph;

pub use proof_graph::{
    BeadOwner, ClaimId, ClaimNode, ClaimStatus, EvidenceId, EvidenceKind, EvidenceNode,
    FreshnessWindow, PROOF_GRAPH_SCHEMA, ProofGap, ProofGapId, ProofGapStatus, ProofGraph,
    ProofGraphError, RedactionClass, RerunCommand, RerunCommandId, SuggestedActionId,
    SuggestedNextAction, SupportEdge, SupportRelationship, TruthSource,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_exports_audit_types() {
        // Verify AuditEvent and AuditHead are accessible
        fn _audit_exists(_e: AuditEvent, _h: AuditHead, _r: DecisionReceipt) {}
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
