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
        self.entries
            .iter()
            .filter(|(candidate, _)| is_scope_prefix(candidate, scope))
            .max_by_key(|(candidate, _)| candidate.len())
            .map_or(0, |(_, counter)| *counter)
    }

    /// Merge another vector into this one, keeping the freshest effective
    /// counter for every explicit scope present in either vector.
    pub fn merge(&mut self, other: &Self) {
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

fn normalize_scope(scope: &str) -> String {
    let trimmed = scope.trim();
    if trimmed.is_empty() {
        "z".to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_scope_prefix(candidate: &str, scope: &str) -> bool {
    candidate == scope
        || scope
            .strip_prefix(candidate)
            .is_some_and(|suffix| suffix.starts_with(':') || suffix.starts_with('/'))
}
