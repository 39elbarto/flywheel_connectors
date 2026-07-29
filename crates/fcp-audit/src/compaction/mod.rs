//! Audit-chain compaction helpers.

pub mod reservoir;

pub use reservoir::{
    ReservoirCompaction, ReservoirCompactionError, ReservoirCompactionReport, ReservoirCompactor,
    compact_entries,
};
