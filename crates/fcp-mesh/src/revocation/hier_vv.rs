//! Hierarchical version vectors for revocation freshness.
//!
//! A path such as `z:work:team-a` inherits the nearest ancestor counter unless
//! it has its own explicit counter. This lets a revocation frontier describe a
//! large zone subtree with one entry while still permitting targeted overrides.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Partial-order relationship between two version vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionVectorOrder {
    /// Both vectors describe the same frontier for all compared scopes.
    Equal,
    /// `self` is at least as fresh as `other` for every compared scope and
    /// newer for at least one scope.
    Dominates,
    /// `other` is at least as fresh as `self` for every compared scope and
    /// newer for at least one scope.
    DominatedBy,
    /// Each vector is newer for at least one independent scope.
    Concurrent,
}

impl VersionVectorOrder {
    /// Stable observability label for this partial-order relationship.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "equal",
            Self::Dominates => "dominates",
            Self::DominatedBy => "dominated_by",
            Self::Concurrent => "concurrent",
        }
    }
}

/// Freshness action for a revocation frontier update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFreshnessAction {
    /// Apply or replay the update.
    Accept,
    /// Reject because the local frontier already dominates the update.
    RejectStale,
}

impl RevocationFreshnessAction {
    /// Stable observability label for this decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::RejectStale => "reject_stale",
        }
    }
}

/// Result of comparing an incoming revocation frontier with local state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationFreshnessDecision {
    /// Scope the incoming update advances.
    pub scope: String,
    /// Local effective counter for `scope` before the update.
    pub local_counter: u64,
    /// Incoming counter advertised by the push.
    pub incoming_counter: u64,
    /// Hierarchical-vector partial order.
    pub order: VersionVectorOrder,
    /// Decision derived from the partial order.
    pub action: RevocationFreshnessAction,
}

impl RevocationFreshnessDecision {
    /// Whether the incoming update should be applied.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self.action, RevocationFreshnessAction::Accept)
    }

    /// Stable label for `fcp.mesh.revocation.freshness` telemetry.
    #[must_use]
    pub const fn hier_vv_status(&self) -> &'static str {
        self.order.as_str()
    }

    /// Stable decision label for `fcp.mesh.revocation.freshness` telemetry.
    #[must_use]
    pub const fn decision_label(&self) -> &'static str {
        self.action.as_str()
    }
}

/// Sparse hierarchical vector keyed by zone/subtree path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchicalVersionVector {
    entries: BTreeMap<String, u64>,
}

impl HierarchicalVersionVector {
    /// Create an empty vector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert or replace the counter for a scope.
    pub fn set(&mut self, scope: impl AsRef<str>, counter: u64) {
        let scope = normalize_scope(scope.as_ref());
        self.entries.insert(scope, counter);
    }

    /// Increment a scope counter and return the new value.
    pub fn increment(&mut self, scope: impl AsRef<str>) -> u64 {
        let scope = normalize_scope(scope.as_ref());
        let next = self
            .entries
            .get(&scope)
            .copied()
            .unwrap_or_default()
            .saturating_add(1);
        self.entries.insert(scope, next);
        next
    }

    /// Exact stored counter for a scope, if present.
    #[must_use]
    pub fn exact(&self, scope: &str) -> Option<u64> {
        self.entries.get(scope.trim()).copied()
    }

    /// Effective counter for a scope after ancestor inheritance.
    #[must_use]
    pub fn counter_for(&self, scope: &str) -> u64 {
        let scope = scope.trim();
        if scope.is_empty() {
            return 0;
        }

        if let Some(counter) = self.entries.get(scope) {
            return *counter;
        }

        for (index, separator) in scope.char_indices().rev() {
            if matches!(separator, ':' | '/') {
                let candidate = &scope[..index];
                if candidate.is_empty() {
                    continue;
                }
                if let Some(counter) = self.entries.get(candidate) {
                    return *counter;
                }
            }
        }

        0
    }

    /// Merge another vector into this one, keeping the freshest effective
    /// counter for every explicit scope present in either vector.
    pub fn merge(&mut self, other: &Self) {
        if self.entries.len() == other.entries.len() && self.entries.keys().eq(other.entries.keys())
        {
            for (counter, other_counter) in self.entries.values_mut().zip(other.entries.values()) {
                *counter = (*counter).max(*other_counter);
            }
            return;
        }

        let scopes = self.comparison_scopes(other);
        for scope in scopes {
            let counter = self.counter_for(&scope).max(other.counter_for(&scope));
            self.entries.insert(scope, counter);
        }
    }

    /// Compare two vectors using vector-clock partial ordering.
    #[must_use]
    pub fn compare(&self, other: &Self) -> VersionVectorOrder {
        let mut self_newer = false;
        let mut other_newer = false;

        for scope in self.comparison_scopes(other) {
            let left = self.counter_for(&scope);
            let right = other.counter_for(&scope);
            self_newer |= left > right;
            other_newer |= right > left;
            if self_newer && other_newer {
                return VersionVectorOrder::Concurrent;
            }
        }

        match (self_newer, other_newer) {
            (false, false) => VersionVectorOrder::Equal,
            (true, false) => VersionVectorOrder::Dominates,
            (false, true) => VersionVectorOrder::DominatedBy,
            (true, true) => VersionVectorOrder::Concurrent,
        }
    }

    /// Whether this vector is at least as fresh as `other`.
    #[must_use]
    pub fn dominates(&self, other: &Self) -> bool {
        matches!(
            self.compare(other),
            VersionVectorOrder::Equal | VersionVectorOrder::Dominates
        )
    }

    /// Number of explicit scopes stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no explicit scopes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Canonical CBOR size for storage-budget checks.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails.
    pub fn canonical_len(&self) -> Result<usize, String> {
        fcp_cbor::to_canonical_cbor(self)
            .map(|bytes| bytes.len())
            .map_err(|error| format!("failed to encode HierVV: {error}"))
    }

    fn comparison_scopes(&self, other: &Self) -> Vec<String> {
        let mut scopes = self.entries.keys().cloned().collect::<Vec<_>>();
        scopes.extend(other.entries.keys().cloned());
        scopes.sort();
        scopes.dedup();
        scopes
    }
}

/// Local revocation freshness frontier for mesh priority pushes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationFreshnessFrontier {
    vector: HierarchicalVersionVector,
}

impl RevocationFreshnessFrontier {
    /// Create an empty freshness frontier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vector: HierarchicalVersionVector::new(),
        }
    }

    /// Create a frontier with one explicit scope counter.
    #[must_use]
    pub fn from_counter(scope: impl AsRef<str>, counter: u64) -> Self {
        let mut vector = HierarchicalVersionVector::new();
        vector.set(scope, counter);
        Self { vector }
    }

    /// Borrow the underlying hierarchical vector.
    #[must_use]
    pub const fn vector(&self) -> &HierarchicalVersionVector {
        &self.vector
    }

    /// Effective local counter for a scope after ancestor inheritance.
    #[must_use]
    pub fn counter_for(&self, scope: &str) -> u64 {
        self.vector.counter_for(scope)
    }

    /// Evaluate an incoming revocation counter without mutating local state.
    #[must_use]
    pub fn evaluate(
        &self,
        scope: impl AsRef<str>,
        incoming_counter: u64,
    ) -> RevocationFreshnessDecision {
        let scope = normalize_scope(scope.as_ref());
        let local_counter = self.vector.counter_for(&scope);
        let incoming = Self::incoming_vector(&scope, incoming_counter);
        let order = incoming.compare(&self.vector);
        let action = match order {
            VersionVectorOrder::DominatedBy => RevocationFreshnessAction::RejectStale,
            VersionVectorOrder::Equal
            | VersionVectorOrder::Dominates
            | VersionVectorOrder::Concurrent => RevocationFreshnessAction::Accept,
        };

        RevocationFreshnessDecision {
            scope,
            local_counter,
            incoming_counter,
            order,
            action,
        }
    }

    /// Evaluate and apply an incoming revocation counter if it is not stale.
    pub fn observe(
        &mut self,
        scope: impl AsRef<str>,
        incoming_counter: u64,
    ) -> RevocationFreshnessDecision {
        let decision = self.evaluate(scope, incoming_counter);
        if decision.is_accepted() {
            self.vector
                .merge(&Self::incoming_vector(&decision.scope, incoming_counter));
        }
        decision
    }

    /// Merge a persisted or reconciled frontier without allowing rollback.
    ///
    /// Returns the relationship of `incoming` to the local frontier before any
    /// merge. Incoming frontiers that local state already dominates are
    /// rejected as stale; equal, dominating, and concurrent frontiers are
    /// merged by keeping the freshest effective counter per scope.
    pub fn reconcile(&mut self, incoming: &Self) -> VersionVectorOrder {
        let order = incoming.vector.compare(&self.vector);
        if !matches!(order, VersionVectorOrder::DominatedBy) {
            self.vector.merge(&incoming.vector);
        }
        order
    }

    /// Canonical CBOR size of the stored frontier.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization fails.
    pub fn canonical_len(&self) -> Result<usize, String> {
        self.vector.canonical_len()
    }

    fn incoming_vector(scope: &str, counter: u64) -> HierarchicalVersionVector {
        let mut incoming = HierarchicalVersionVector::new();
        incoming.set(scope, counter);
        incoming
    }
}

fn normalize_scope(scope: &str) -> String {
    let trimmed = scope.trim();
    if trimmed.is_empty() {
        "z".to_string()
    } else {
        trimmed.to_string()
    }
}
