//! Migration substrate for connector process handoff.
//!
//! This crate starts with deterministic, testable CRIU policy primitives:
//! pre-copy dirty-rate decisions, post-copy page-fault forwarding decisions,
//! and a dirty-page bitmap abstraction that can be backed by Linux soft-dirty
//! tracking or a page-walker fallback.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod criu;

pub use criu::dirty_tracker::{
    DirtyPageBitmap, DirtyTracker, DirtyTrackerError, DirtyTrackerHealth, DirtyTrackerMode,
    SoftDirtyPageState, SoftDirtyProc, SoftDirtyReader, StaticSoftDirtyReader, virtual_page_index,
};
pub use criu::postcopy::{
    DEFAULT_PAGE_FAULT_TIMEOUT_MS, PageFaultSource, PageFetch, PostCopyDecision,
    PostCopyFallbackDecision, PostCopyForwarder, PostCopyOutcome,
};
pub use criu::precopy::{
    Bandwidth, PreCopyController, PreCopyDecision, PreCopyOutcome, PreCopyReport, PreCopyRoundLog,
    Workload, run_precopy,
};
