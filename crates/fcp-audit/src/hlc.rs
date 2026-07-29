//! Hybrid logical clock primitives for audit-chain ordering.
//!
//! The clock follows the Kulkarni-Demirbas HLC update rules: physical time is
//! used when it moves forward, while a logical counter preserves monotonicity
//! across local clock regressions and remote observations.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// HLC timestamp ordered by physical time, logical counter, then node id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HybridLogicalTimestamp {
    /// Physical wall-clock component in milliseconds.
    pub physical_ms: u64,
    /// Logical counter used when physical time does not advance.
    pub logical: u32,
    /// Stable node id that produced this timestamp.
    pub node_id: String,
}

impl HybridLogicalTimestamp {
    /// Create a timestamp from explicit parts.
    #[must_use]
    pub fn new(physical_ms: u64, logical: u32, node_id: impl Into<String>) -> Self {
        Self {
            physical_ms,
            logical,
            node_id: node_id.into(),
        }
    }

    /// Create a timestamp with logical counter zero.
    #[must_use]
    pub fn from_physical(physical_ms: u64, node_id: impl Into<String>) -> Self {
        Self::new(physical_ms, 0, node_id)
    }

    /// Return the timestamp with the local node id replaced.
    #[must_use]
    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = node_id.into();
        self
    }
}

impl Ord for HybridLogicalTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.physical_ms
            .cmp(&other.physical_ms)
            .then_with(|| self.logical.cmp(&other.logical))
            .then_with(|| self.node_id.cmp(&other.node_id))
    }
}

impl PartialOrd for HybridLogicalTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Mutable HLC state for one audit-producing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridLogicalClock {
    node_id: String,
    last: HybridLogicalTimestamp,
}

impl HybridLogicalClock {
    /// Create a clock with no prior events.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        Self {
            last: HybridLogicalTimestamp::from_physical(0, node_id.clone()),
            node_id,
        }
    }

    /// Return the stable local node id.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Return the latest produced or observed local timestamp.
    #[must_use]
    pub const fn last(&self) -> &HybridLogicalTimestamp {
        &self.last
    }

    /// Produce a local timestamp at the supplied physical time.
    ///
    /// If `physical_ms` moves backward or stays equal, the logical counter
    /// advances so the returned timestamp remains strictly greater than the
    /// previous local timestamp.
    #[must_use]
    pub fn tick(&mut self, physical_ms: u64) -> HybridLogicalTimestamp {
        let next = if physical_ms > self.last.physical_ms {
            HybridLogicalTimestamp::from_physical(physical_ms, self.node_id.clone())
        } else {
            self.increment_at(self.last.physical_ms)
        };
        self.last = next.clone();
        next
    }

    /// Observe a remote timestamp and produce the next local HLC timestamp.
    #[must_use]
    pub fn merge(
        &mut self,
        remote: &HybridLogicalTimestamp,
        physical_ms: u64,
    ) -> HybridLogicalTimestamp {
        let max_physical = physical_ms
            .max(self.last.physical_ms)
            .max(remote.physical_ms);

        let logical = if max_physical == self.last.physical_ms && max_physical == remote.physical_ms
        {
            self.last.logical.max(remote.logical).saturating_add(1)
        } else if max_physical == self.last.physical_ms {
            self.last.logical.saturating_add(1)
        } else if max_physical == remote.physical_ms {
            remote.logical.saturating_add(1)
        } else {
            0
        };

        let next = if logical == u32::MAX {
            HybridLogicalTimestamp::from_physical(
                max_physical.saturating_add(1),
                self.node_id.clone(),
            )
        } else {
            HybridLogicalTimestamp::new(max_physical, logical, self.node_id.clone())
        };
        self.last = next.clone();
        next
    }

    fn increment_at(&self, physical_ms: u64) -> HybridLogicalTimestamp {
        if self.last.logical == u32::MAX {
            HybridLogicalTimestamp::from_physical(
                physical_ms.saturating_add(1),
                self.node_id.clone(),
            )
        } else {
            HybridLogicalTimestamp::new(
                physical_ms,
                self.last.logical.saturating_add(1),
                self.node_id.clone(),
            )
        }
    }
}
