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
}
