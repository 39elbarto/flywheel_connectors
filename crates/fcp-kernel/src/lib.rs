//! # FCP Kernel
//!
//! Canonical owner of execution lifecycle semantics for the Flywheel Connector
//! Protocol. This crate defines the types, traits, and state machines that govern
//! how connectors are invoked, sessions managed, operations executed, and deployment
//! lifecycle controlled.
//!
//! ## Semantic Domains Owned
//!
//! - **Invocation protocol**: `InvokeRequest`, `InvokeResponse`, `InvokeStatus`,
//!   `SimulateRequest`, `SimulateResponse`
//! - **Session establishment**: `HandshakeRequest`, `HandshakeResponse`, `SessionId`
//! - **Connector traits**: `FcpConnector`, `RequestResponse`, `Streaming`,
//!   `Bidirectional`, `Polling`, `Webhook`
//! - **Lifecycle state machine**: `LifecycleState`, `LifecycleManager`,
//!   `LifecycleTransition`
//! - **Operation metadata**: `OperationInfo`, `Introspection`, `AgentHint`
//! - **Execution control**: `CancelReason`, `CleanupBehavior`, `ProgressUpdate`
//!
//! ## Migration Note
//!
//! This crate currently re-exports types from `fcp-core`. As the FCP3 migration
//! progresses, type definitions will move here and `fcp-core` will re-export from
//! this crate instead. Consumers should target `fcp_kernel::` imports for new code.

#![forbid(unsafe_code)]

// ── Invocation Protocol ──────────────────────────────────────────

pub use fcp_core::{
    InvokeContext, InvokeRequest, InvokeResponse, InvokeStatus, InvokeValidationError,
    RequestId, ResponseMetadata,
};

// ── Handshake / Session ──────────────────────────────────────────

pub use fcp_core::{
    AuthCaps, EventCaps, HandshakeRequest, HandshakeResponse, HostInfo, SessionId, TransportCaps,
};

// ── Simulate ─────────────────────────────────────────────────────

pub use fcp_core::{SimulateRequest, SimulateResponse};

// ── Subscription / Events ────────────────────────────────────────

pub use fcp_core::{EventAck, EventData, EventEnvelope, EventNack};

// ── Connector Traits ─────────────────────────────────────────────

pub use fcp_core::{
    BaseConnector, Bidirectional, ConnectorMetrics, FcpConnector, Polling, RequestResponse,
    Streaming, Webhook,
};

// ── Introspection / Operation Metadata ───────────────────────────

pub use fcp_core::{
    AgentHint, ApprovalMode, EventInfo, Introspection, OperationInfo, ResourceTypeInfo,
};

// ── Lifecycle State Machine ──────────────────────────────────────

pub use fcp_core::{
    CanaryPolicy, CrashLoopDetector, HealthMetrics, LifecycleError, LifecycleManager,
    LifecycleRecord, LifecycleState, LifecycleStatus, LifecycleTransition, TransitionReason,
};

// ── Health / Self-Check ──────────────────────────────────────────

pub use fcp_core::{HealthSnapshot, HealthState, SelfCheckReport, SelfCheckStatus};

// ── Identity Types (re-exported for convenience) ─────────────────

pub use fcp_core::{ConnectorId, InstanceId, OperationId};

// ── Error Types ──────────────────────────────────────────────────

pub use fcp_core::{FcpError, FcpResult};

// ── Execution Control (PENDING-CARVE: definitions will move here) ─

// These types are currently defined in fcp-host but should be platform-canonical.
// They will be defined here and re-exported by fcp-host in a future phase.
//
// - CancelReason (from fcp-host::cancellation)
// - CleanupBehavior (from fcp-host::cancellation)
// - ProgressUpdate (from fcp-host::progress)
// - RolloutDecision (from fcp-host::rollout)
// - RolloutEvidence (from fcp-host::rollout)
// - RolloutObservation (from fcp-host::rollout)

// ── Cost & Usage ─────────────────────────────────────────────────

pub use fcp_core::{CostEstimate, ResourceAvailability, UsageMetric, UsageMetricKind};

// ── Idempotency & Durability ─────────────────────────────────────

pub use fcp_core::{IdempotencyClass, IdempotencyEntry, OperationIntent, OperationReceipt};

// ── Lease & Execution Authority ────────────────────────────────────

pub use fcp_core::{
    Lease, LeaseHandoff, LeaseId, LeasePurpose, LeaseParams, LeaseRequest, LeaseResponse,
    LeaseTransferValidationError, LeaseValidationError,
};

// ── Checkpoint & Recovery ──────────────────────────────────────────

pub use fcp_core::{
    CheckpointAdvanceState, CheckpointChunkError, CheckpointProposal, CheckpointTransferEncoding,
    CheckpointTrigger, CheckpointValidationError, ChunkedCheckpoint, ChunkedObjectManifest,
    ComputationCheckpoint, ForkDetectionResult, ForkEvidence, FreshnessResult,
    MigrationCapabilityContext,
};

// ── Computation Migration & State ──────────────────────────────────

pub use fcp_core::{
    ComputationMigrationError, ConnectorStateDelta, ConnectorStateModel, ConnectorStateObject,
    ConnectorStateRoot, ConnectorStateSnapshot, CrdtType, CursorState, ForkEvent, ForkResolution,
    ForkResolutionOutcome, MigratableComputation, MigratableComputationState,
    StateForkDetectionResult, StateForkDetector,
};

// ── Budget & Resource Accounting ───────────────────────────────────

pub use fcp_core::{
    BudgetEnforcement, BudgetStatus, UsageBudgetLimit, UsageBudgetPolicy, UsageBudgetSnapshot,
    UsageBudgetUsage,
};

// ── Rate Limiting (execution-level) ────────────────────────────────

pub use fcp_core::{
    AggregatedRateLimits, BackpressureLevel, BackpressureSignal, LimitType, RateLimitConfig,
    RateLimitDeclarationError, RateLimitDeclarations, RateLimitEnforcement, RateLimitInfo,
    RateLimitPool, RateLimitScope, RateLimitStatus, RateLimitUnit, ThrottleViolation,
    ThrottleViolationInput,
};

// ── Quorum & Consensus (execution safety) ──────────────────────────

pub use fcp_core::{
    DegradedModeState, NodeSignature, QuorumFailureReason, QuorumPolicy, QuorumPurpose,
    QuorumVerificationResult, RiskTier, SignatureSet,
};

// ── Shutdown & Drain ───────────────────────────────────────────────

pub use fcp_core::{ShutdownAck, ShutdownRequest};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_exports_invoke_types() {
        // Verify core invocation types are accessible
        let _: InvokeStatus = InvokeStatus::Ok;
        let _: ApprovalMode = ApprovalMode::Interactive;
    }

    #[test]
    fn kernel_exports_lifecycle_types() {
        // Verify lifecycle state machine types are accessible
        let _: LifecycleState = LifecycleState::Pending;
    }

    #[test]
    fn kernel_exports_health_types() {
        let _: HealthState = HealthState::Ready;
        let _: SelfCheckStatus = SelfCheckStatus::Ok;
    }

    #[test]
    fn kernel_exports_connector_id() {
        let id = ConnectorId::from_static("fcp.test");
        assert_eq!(id.as_str(), "fcp.test");
    }

    #[test]
    fn kernel_exports_operation_id() {
        let id = OperationId::from_static("test.op");
        assert_eq!(id.as_str(), "test.op");
    }

    #[test]
    fn kernel_exports_lease_types() {
        let _: LeasePurpose = LeasePurpose::OperationExecution;
        let _: LeasePurpose = LeasePurpose::ComputationMigration;
        let _: LeasePurpose = LeasePurpose::ConnectorStateWrite;
    }

    #[test]
    fn kernel_exports_checkpoint_types() {
        // CheckpointTrigger variants have data fields, just verify the type exists
        let _trigger: fn(u64, u64) -> CheckpointTrigger = |elapsed, threshold| {
            CheckpointTrigger::TimeElapsed {
                elapsed_secs: elapsed,
                threshold_secs: threshold,
            }
        };
    }

    #[test]
    fn kernel_exports_computation_migration_types() {
        let _: MigratableComputationState = MigratableComputationState::Running;
        let _: MigratableComputationState = MigratableComputationState::Suspended;
        let _: ConnectorStateModel = ConnectorStateModel::Stateless;
    }

    #[test]
    fn kernel_exports_budget_types() {
        let _: BudgetEnforcement = BudgetEnforcement::Warn;
        let _: BudgetEnforcement = BudgetEnforcement::Deny;
        let _: BudgetStatus = BudgetStatus::Ok;
    }

    #[test]
    fn kernel_exports_rate_limit_types() {
        let _: LimitType = LimitType::Rpm;
        let _: LimitType = LimitType::Concurrent;
        let _: BackpressureLevel = BackpressureLevel::Normal;
        let _: RateLimitEnforcement = RateLimitEnforcement::Hard;
    }

    #[test]
    fn kernel_exports_quorum_types() {
        let _: RiskTier = RiskTier::Safe;
        let _: RiskTier = RiskTier::Risky;
        let _: QuorumPurpose = QuorumPurpose::AuditHead;
    }

    #[test]
    fn kernel_exports_shutdown_types() {
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 5000,
            drain: true,
            reason: Some("test".into()),
        };
        assert!(req.drain);
        assert_eq!(req.deadline_ms, 5000);
    }

    #[test]
    fn kernel_exports_idempotency_types() {
        let _: IdempotencyClass = IdempotencyClass::Strict;
    }
}
