//! FCPS-aligned object and symbol stores (placement, repair, retention).
//!
//! This crate implements the storage layer from `FCP_Specification_V2.md`:
//!
//! # Overview
//!
//! - **Object Store**: Content-addressed storage for complete mesh objects
//! - **Symbol Store**: Storage for `RaptorQ` symbols enabling partial availability
//! - **Coverage Evaluation**: Quantifiable offline resilience metrics (basis points)
//! - **Repair Controller**: Bounded, convergent repair with rate limiting
//! - **Garbage Collection**: Reachability-based GC with retention classes
//! - **Quarantine Store**: Admission pipeline for untrusted objects
//!
//! # Design Principles
//!
//! 1. **Coverage is measurable**: All metrics use fixed-point basis points for
//!    interop stability across implementations.
//!
//! 2. **Repair is bounded and convergent**: Repair loops push coverage toward
//!    policy targets with rate limiting and admission control.
//!
//! 3. **Retention + GC roots are explicit**: Clear semantics for Pinned, Lease,
//!    and Ephemeral retention with zone checkpoints as canonical roots.
//!
//! 4. **Quarantine by default**: Unknown objects enter a bounded quarantine
//!    store and require explicit promotion to prevent storage exhaustion.

#![forbid(unsafe_code)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::option_if_let_else)]

mod coverage;
mod error;
mod gc;
mod object_store;
mod offline;
mod quarantine;
mod repair;
mod symbol_store;

pub use coverage::{CoverageEvaluation, CoverageHealth, SymbolDistribution};
pub use error::{
    GcError, LifecycleSnapshotError, ObjectStoreError, QuarantineError, RepairError,
    SymbolStoreError,
};
pub use gc::{
    GarbageCollector, GcConfig, GcDecision, GcDecisionAction, GcReasonCode, GcResult, GcRoots,
    GcRunReport, GcTranscript,
};
pub use object_store::{
    LifecycleRootObservation, LifecycleRootRole, LifecycleRootStatus, MemoryObjectStore,
    MemoryObjectStoreConfig, ObjectLeaseState, ObjectLifecycleSnapshot, ObjectStore,
    ZoneLifecycleSnapshot, snapshot_zone_lifecycle,
};
pub use quarantine::{
    ObjectAdmissionClass, ObjectAdmissionPolicy, PromotionReason, QuarantineStats, QuarantineStore,
    QuarantinedObject,
};
pub use repair::{
    RepairController, RepairControllerConfig, RepairCycleBudget, RepairCycleUsage, RepairPermit,
    RepairPlan, RepairPlanAction, RepairPlanningOptions, RepairPolicyTargets, RepairReasonCode,
    RepairRequest, RepairResult, RepairSloMetrics, RepairStats, TargetedRepairRequest,
};
pub use symbol_store::{
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
    StoredSymbol, SymbolMeta, SymbolStore,
};

pub use offline::{
    AccessPatternTracker, OfflineAccess, OfflineCapability, OfflineStatus, OfflineSummary,
};
