//! Conflict-free replicated data types (CRDTs) for connector state.
//!
//! These are mesh-friendly, deterministic CRDTs for state replication.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::TailscaleNodeId;
use std::fmt;

/// Actor identifier for CRDT operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CrdtActorId(String);

impl CrdtActorId {
    /// Create a new actor id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CrdtActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for CrdtActorId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for CrdtActorId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for CrdtActorId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<TailscaleNodeId> for CrdtActorId {
    fn from(value: TailscaleNodeId) -> Self {
        Self(value.as_str().to_string())
    }
}

impl From<&TailscaleNodeId> for CrdtActorId {
    fn from(value: &TailscaleNodeId) -> Self {
        Self(value.as_str().to_string())
    }
}

/// LWW entry with timestamp and actor tie-breaker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwEntry<V> {
    pub value: V,
    pub timestamp: u64,
    pub actor: CrdtActorId,
}

impl<V> LwwEntry<V> {
    fn wins_over(&self, other: &Self) -> bool {
        if self.timestamp == other.timestamp {
            self.actor > other.actor
        } else {
            self.timestamp > other.timestamp
        }
    }
}

/// Last-write-wins map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K: Ord + Serialize, V: Serialize",
    deserialize = "K: Ord + Deserialize<'de>, V: Deserialize<'de>"
))]
pub struct LwwMap<K, V> {
    entries: BTreeMap<K, LwwEntry<V>>,
}

impl<K, V> LwwMap<K, V>
where
    K: Ord + Clone,
    V: Clone + PartialEq,
{
    pub fn insert(&mut self, key: K, value: V, timestamp: u64, actor: CrdtActorId) {
        let entry = LwwEntry {
            value,
            timestamp,
            actor,
        };
        match self.entries.get(&key) {
            Some(existing) if !entry.wins_over(existing) => {}
            _ => {
                self.entries.insert(key, entry);
            }
        }
    }

    pub fn merge(&mut self, other: &Self) {
        for (key, entry) in &other.entries {
            match self.entries.get(key) {
                Some(existing) if !entry.wins_over(existing) => {}
                _ => {
                    self.entries.insert(key.clone(), entry.clone());
                }
            }
        }
    }

    #[must_use]
    pub fn get(&self, key: &K) -> Option<&LwwEntry<V>> {
        self.entries.get(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Unique tag for OR-Set operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OrSetTag {
    pub actor: CrdtActorId,
    pub nonce: u64,
}

impl OrSetTag {
    #[must_use]
    pub const fn new(actor: CrdtActorId, nonce: u64) -> Self {
        Self { actor, nonce }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct OrSetTags {
    adds: BTreeSet<OrSetTag>,
    removes: BTreeSet<OrSetTag>,
}

/// Observed-remove set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Ord + Serialize",
    deserialize = "T: Ord + Deserialize<'de>"
))]
pub struct OrSet<T> {
    entries: BTreeMap<T, OrSetTags>,
}

impl<T> OrSet<T>
where
    T: Ord + Clone,
{
    pub fn add(&mut self, value: T, tag: OrSetTag) {
        let tags = self.entries.entry(value).or_default();
        if !tags.removes.contains(&tag) {
            tags.adds.insert(tag);
        }
    }

    /// Remove all observed tags for a value.
    pub fn remove_observed(&mut self, value: &T) {
        if let Some(tags) = self.entries.get_mut(value) {
            tags.removes.extend(tags.adds.iter().cloned());
            tags.adds.clear();
        }
    }

    #[must_use]
    pub fn contains(&self, value: &T) -> bool {
        self.entries
            .get(value)
            .is_some_and(|tags| !tags.adds.is_empty())
    }

    pub fn merge(&mut self, other: &Self) {
        for (value, tags) in &other.entries {
            let entry = self.entries.entry(value.clone()).or_default();
            entry.removes.extend(tags.removes.iter().cloned());

            for tag in &tags.adds {
                if !entry.removes.contains(tag) {
                    entry.adds.insert(tag.clone());
                }
            }

            // Cleanup existing adds that are now removed
            entry.adds.retain(|tag| !entry.removes.contains(tag));
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, tags)| !tags.adds.is_empty())
            .count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn values(&self) -> Vec<T> {
        self.entries
            .iter()
            .filter(|(_, tags)| !tags.adds.is_empty())
            .map(|(value, _)| value.clone())
            .collect()
    }
}

/// Grow-only counter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GCounter {
    pub counts: BTreeMap<CrdtActorId, u64>,
}

impl GCounter {
    pub fn increment(&mut self, actor: CrdtActorId, delta: u64) {
        let entry = self.counts.entry(actor).or_insert(0);
        *entry = entry.saturating_add(delta);
    }

    #[must_use]
    pub fn value(&self) -> u128 {
        self.counts
            .values()
            .fold(0u128, |acc, value| acc.saturating_add(u128::from(*value)))
    }

    pub fn merge(&mut self, other: &Self) {
        for (actor, value) in &other.counts {
            let entry = self.counts.entry(actor.clone()).or_insert(0);
            if *entry < *value {
                *entry = *value;
            }
        }
    }
}

/// PN-Counter (positive-negative).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PnCounter {
    pub positive: GCounter,
    pub negative: GCounter,
}

impl PnCounter {
    pub fn increment(&mut self, actor: CrdtActorId, delta: u64) {
        self.positive.increment(actor, delta);
    }

    pub fn decrement(&mut self, actor: CrdtActorId, delta: u64) {
        self.negative.increment(actor, delta);
    }

    #[must_use]
    pub fn value(&self) -> i64 {
        let pos = self.positive.value();
        let neg = self.negative.value();

        if pos >= neg {
            let diff = pos - neg;
            // Clamp positive overflow to i64::MAX
            if diff > i64::MAX as u128 {
                i64::MAX
            } else {
                i64::try_from(diff).unwrap_or(i64::MAX)
            }
        } else {
            let diff = neg - pos;
            // Clamp negative overflow to i64::MIN
            // |i64::MIN| = i64::MAX + 1
            if diff > i64::MAX as u128 {
                i64::MIN
            } else {
                -i64::try_from(diff).unwrap_or(i64::MAX)
            }
        }
    }

    pub fn merge(&mut self, other: &Self) {
        self.positive.merge(&other.positive);
        self.negative.merge(&other.negative);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(name: &str) -> CrdtActorId {
        CrdtActorId::new(name)
    }

    fn tag(name: &str, nonce: u64) -> OrSetTag {
        OrSetTag::new(actor(name), nonce)
    }

    // ---- CrdtActorId tests ----

    #[test]
    fn actor_id_display_and_conversions() {
        let a = CrdtActorId::new("node-1");
        assert_eq!(a.as_str(), "node-1");
        assert_eq!(a.to_string(), "node-1");
        assert_eq!(a.as_ref(), "node-1");

        let b: CrdtActorId = "node-2".into();
        assert_eq!(b.as_str(), "node-2");

        let c: CrdtActorId = String::from("node-3").into();
        assert_eq!(c.as_str(), "node-3");
    }

    #[test]
    fn actor_id_from_tailscale_node_id() {
        let ts = TailscaleNodeId::new("ts-node-1");
        let a: CrdtActorId = ts.into();
        assert_eq!(a.as_str(), "ts-node-1");

        let ts2 = TailscaleNodeId::new("ts-node-2");
        let b: CrdtActorId = (&ts2).into();
        assert_eq!(b.as_str(), "ts-node-2");
    }

    #[test]
    fn actor_id_ordering() {
        let a = actor("aaa");
        let b = actor("bbb");
        assert!(a < b);
        assert!(b > a);
    }

    // ---- LwwEntry tests ----

    #[test]
    fn lww_entry_higher_timestamp_wins() {
        let newer = LwwEntry {
            value: "new",
            timestamp: 200,
            actor: actor("A"),
        };
        let older = LwwEntry {
            value: "old",
            timestamp: 100,
            actor: actor("A"),
        };
        assert!(newer.wins_over(&older));
        assert!(!older.wins_over(&newer));
    }

    #[test]
    fn lww_entry_same_timestamp_actor_tiebreak() {
        let a = LwwEntry {
            value: 1,
            timestamp: 100,
            actor: actor("aaa"),
        };
        let b = LwwEntry {
            value: 2,
            timestamp: 100,
            actor: actor("bbb"),
        };
        // "bbb" > "aaa" lexicographically, so b wins
        assert!(b.wins_over(&a));
        assert!(!a.wins_over(&b));
    }

    #[test]
    fn lww_entry_identical_neither_wins() {
        let a = LwwEntry {
            value: 1,
            timestamp: 100,
            actor: actor("same"),
        };
        let b = LwwEntry {
            value: 1,
            timestamp: 100,
            actor: actor("same"),
        };
        // Neither wins over the other (equal)
        assert!(!a.wins_over(&b));
        assert!(!b.wins_over(&a));
    }

    // ---- LwwMap tests ----

    #[test]
    fn lww_map_insert_and_get() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("key".to_string(), 42, 100, actor("A"));

        let entry = map.get(&"key".to_string()).expect("key should exist");
        assert_eq!(entry.value, 42);
        assert_eq!(entry.timestamp, 100);
    }

    #[test]
    fn lww_map_newer_overwrites_older() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("k".to_string(), 1, 100, actor("A"));
        map.insert("k".to_string(), 2, 200, actor("A"));

        assert_eq!(map.get(&"k".to_string()).unwrap().value, 2);
    }

    #[test]
    fn lww_map_older_does_not_overwrite_newer() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("k".to_string(), 1, 200, actor("A"));
        map.insert("k".to_string(), 2, 100, actor("A")); // older timestamp

        assert_eq!(map.get(&"k".to_string()).unwrap().value, 1);
    }

    #[test]
    fn lww_map_len_and_is_empty() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);

        map.insert("a".to_string(), 1, 100, actor("A"));
        map.insert("b".to_string(), 2, 100, actor("A"));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
    }

    #[test]
    fn lww_map_merge_takes_newer_values() {
        let mut map1: LwwMap<String, i32> = LwwMap::default();
        map1.insert("k".to_string(), 1, 100, actor("A"));

        let mut map2: LwwMap<String, i32> = LwwMap::default();
        map2.insert("k".to_string(), 2, 200, actor("B"));

        map1.merge(&map2);
        assert_eq!(map1.get(&"k".to_string()).unwrap().value, 2);
    }

    #[test]
    fn lww_map_merge_keeps_newer_local() {
        let mut map1: LwwMap<String, i32> = LwwMap::default();
        map1.insert("k".to_string(), 1, 200, actor("A"));

        let mut map2: LwwMap<String, i32> = LwwMap::default();
        map2.insert("k".to_string(), 2, 100, actor("B"));

        map1.merge(&map2);
        assert_eq!(map1.get(&"k".to_string()).unwrap().value, 1);
    }

    #[test]
    fn lww_map_merge_adds_new_keys() {
        let mut map1: LwwMap<String, i32> = LwwMap::default();
        map1.insert("a".to_string(), 1, 100, actor("A"));

        let mut map2: LwwMap<String, i32> = LwwMap::default();
        map2.insert("b".to_string(), 2, 100, actor("B"));

        map1.merge(&map2);
        assert_eq!(map1.len(), 2);
        assert_eq!(map1.get(&"a".to_string()).unwrap().value, 1);
        assert_eq!(map1.get(&"b".to_string()).unwrap().value, 2);
    }

    #[test]
    fn lww_map_merge_is_commutative() {
        let mut a: LwwMap<String, i32> = LwwMap::default();
        a.insert("k".to_string(), 1, 100, actor("X"));

        let mut b: LwwMap<String, i32> = LwwMap::default();
        b.insert("k".to_string(), 2, 200, actor("Y"));

        let mut ab = a.clone();
        ab.merge(&b);

        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(
            ab.get(&"k".to_string()).unwrap().value,
            ba.get(&"k".to_string()).unwrap().value
        );
    }

    #[test]
    fn lww_map_merge_is_idempotent() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("k".to_string(), 42, 100, actor("A"));

        let snapshot = map.clone();
        map.merge(&snapshot);
        assert_eq!(map, snapshot);
    }

    // ---- OrSet tests ----

    #[test]
    fn or_set_add_and_contains() {
        let mut set: OrSet<String> = OrSet::default();
        assert!(!set.contains(&"x".to_string()));

        set.add("x".to_string(), tag("A", 1));
        assert!(set.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_remove_observed() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        assert!(set.contains(&"x".to_string()));

        set.remove_observed(&"x".to_string());
        assert!(!set.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_add_after_remove_with_new_tag() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        set.remove_observed(&"x".to_string());
        assert!(!set.contains(&"x".to_string()));

        // Re-add with a new unique tag
        set.add("x".to_string(), tag("A", 2));
        assert!(set.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_add_with_already_removed_tag_ignored() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        set.remove_observed(&"x".to_string());

        // Re-add with the SAME tag that was removed — should be ignored
        set.add("x".to_string(), tag("A", 1));
        assert!(!set.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_len_and_values() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("a".to_string(), tag("A", 1));
        set.add("b".to_string(), tag("A", 2));
        set.add("c".to_string(), tag("A", 3));

        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());

        let mut vals = set.values();
        vals.sort();
        assert_eq!(vals, vec!["a", "b", "c"]);
    }

    #[test]
    fn or_set_len_excludes_removed() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("a".to_string(), tag("A", 1));
        set.add("b".to_string(), tag("A", 2));
        set.remove_observed(&"a".to_string());

        assert_eq!(set.len(), 1);
        assert_eq!(set.values(), vec!["b".to_string()]);
    }

    #[test]
    fn or_set_merge_concurrent_add_add() {
        let mut set1: OrSet<String> = OrSet::default();
        set1.add("x".to_string(), tag("A", 1));

        let mut set2: OrSet<String> = OrSet::default();
        set2.add("x".to_string(), tag("B", 1));

        set1.merge(&set2);
        // Both adds preserved — element is present
        assert!(set1.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_merge_concurrent_add_remove() {
        // Actor A adds, actor B concurrently adds and removes
        let mut set1: OrSet<String> = OrSet::default();
        set1.add("x".to_string(), tag("A", 1));

        let mut set2: OrSet<String> = OrSet::default();
        set2.add("x".to_string(), tag("B", 1));
        set2.remove_observed(&"x".to_string()); // removes tag B:1

        set1.merge(&set2);
        // A's add (tag A:1) was not in B's remove set, so element persists
        assert!(set1.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_merge_both_removed() {
        let mut set1: OrSet<String> = OrSet::default();
        set1.add("x".to_string(), tag("A", 1));
        set1.remove_observed(&"x".to_string());

        let mut set2: OrSet<String> = OrSet::default();
        set2.add("x".to_string(), tag("A", 1));
        set2.remove_observed(&"x".to_string());

        set1.merge(&set2);
        assert!(!set1.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_merge_is_commutative() {
        let mut a: OrSet<String> = OrSet::default();
        a.add("x".to_string(), tag("A", 1));
        a.add("y".to_string(), tag("A", 2));

        let mut b: OrSet<String> = OrSet::default();
        b.add("x".to_string(), tag("B", 1));
        b.add("z".to_string(), tag("B", 2));

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        let mut vals_ab = ab.values();
        vals_ab.sort();
        let mut vals_ba = ba.values();
        vals_ba.sort();
        assert_eq!(vals_ab, vals_ba);
    }

    #[test]
    fn or_set_merge_is_idempotent() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        set.add("y".to_string(), tag("A", 2));

        let snapshot = set.clone();
        set.merge(&snapshot);
        assert_eq!(set, snapshot);
    }

    // ---- GCounter tests ----

    #[test]
    fn gcounter_starts_at_zero() {
        let counter = GCounter::default();
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn gcounter_increment_single_actor() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 5);
        assert_eq!(counter.value(), 5);

        counter.increment(actor("A"), 3);
        assert_eq!(counter.value(), 8);
    }

    #[test]
    fn gcounter_increment_multiple_actors() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 10);
        counter.increment(actor("B"), 20);
        counter.increment(actor("C"), 30);
        assert_eq!(counter.value(), 60);
    }

    #[test]
    fn gcounter_merge_takes_max_per_actor() {
        let mut c1 = GCounter::default();
        c1.increment(actor("A"), 10);
        c1.increment(actor("B"), 5);

        let mut c2 = GCounter::default();
        c2.increment(actor("A"), 7); // lower than c1's A
        c2.increment(actor("B"), 15); // higher than c1's B
        c2.increment(actor("C"), 20); // new actor

        c1.merge(&c2);
        assert_eq!(*c1.counts.get(&actor("A")).unwrap(), 10); // max(10, 7)
        assert_eq!(*c1.counts.get(&actor("B")).unwrap(), 15); // max(5, 15)
        assert_eq!(*c1.counts.get(&actor("C")).unwrap(), 20); // new
        assert_eq!(c1.value(), 45);
    }

    #[test]
    fn gcounter_merge_is_commutative() {
        let mut a = GCounter::default();
        a.increment(actor("A"), 10);

        let mut b = GCounter::default();
        b.increment(actor("B"), 20);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.value(), ba.value());
    }

    #[test]
    fn gcounter_merge_is_idempotent() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 10);

        let snapshot = counter.clone();
        counter.merge(&snapshot);
        assert_eq!(counter, snapshot);
    }

    #[test]
    fn gcounter_saturating_add() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), u64::MAX);
        counter.increment(actor("A"), 1); // should saturate, not overflow
        assert_eq!(*counter.counts.get(&actor("A")).unwrap(), u64::MAX);
    }

    #[test]
    fn gcounter_value_saturating_sum() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), u64::MAX);
        counter.increment(actor("B"), 1);
        assert_eq!(counter.value(), u128::from(u64::MAX) + 1); // overflows to u64::MAX + 1
    }

    // ---- PnCounter tests ----

    #[test]
    fn pn_counter_starts_at_zero() {
        let counter = PnCounter::default();
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn pn_counter_increment_and_decrement() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 10);
        assert_eq!(counter.value(), 10);

        counter.decrement(actor("A"), 3);
        assert_eq!(counter.value(), 7);
    }

    #[test]
    fn pn_counter_can_go_negative() {
        let mut counter = PnCounter::default();
        counter.decrement(actor("A"), 5);
        assert_eq!(counter.value(), -5);
    }

    #[test]
    fn pn_counter_multiple_actors() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 100);
        counter.decrement(actor("B"), 30);
        counter.increment(actor("C"), 50);
        counter.decrement(actor("A"), 20);
        assert_eq!(counter.value(), 100); // 150 - 50
    }

    #[test]
    fn pn_counter_merge() {
        let mut c1 = PnCounter::default();
        c1.increment(actor("A"), 10);
        c1.decrement(actor("B"), 3);

        let mut c2 = PnCounter::default();
        c2.increment(actor("A"), 5);
        c2.decrement(actor("C"), 2);

        c1.merge(&c2);
        // positive: A=max(10,5)=10
        // negative: B=3, C=2
        assert_eq!(c1.value(), 5); // 10 - (3+2)
    }

    #[test]
    fn pn_counter_merge_is_commutative() {
        let mut a = PnCounter::default();
        a.increment(actor("X"), 10);
        a.decrement(actor("Y"), 3);

        let mut b = PnCounter::default();
        b.increment(actor("Y"), 5);
        b.decrement(actor("X"), 2);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.value(), ba.value());
    }

    #[test]
    fn pn_counter_merge_is_idempotent() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 10);
        counter.decrement(actor("B"), 3);

        let snapshot = counter.clone();
        counter.merge(&snapshot);
        assert_eq!(counter, snapshot);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CrdtActorId – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn actor_id_clone() {
        let a = actor("node-1");
        let cloned = a.clone();
        assert_eq!(a, cloned);
    }

    #[test]
    fn actor_id_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(actor("a"));
        set.insert(actor("a"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn actor_id_serde_roundtrip() {
        let a = actor("node-42");
        let json = serde_json::to_string(&a).unwrap();
        let decoded: CrdtActorId = serde_json::from_str(&json).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn actor_id_equality() {
        assert_eq!(actor("same"), actor("same"));
        assert_ne!(actor("a"), actor("b"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OrSetTag – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn or_set_tag_serde_roundtrip() {
        let t = tag("actor1", 99);
        let json = serde_json::to_string(&t).unwrap();
        let decoded: OrSetTag = serde_json::from_str(&json).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn or_set_tag_equality() {
        assert_eq!(tag("a", 1), tag("a", 1));
        assert_ne!(tag("a", 1), tag("a", 2));
        assert_ne!(tag("a", 1), tag("b", 1));
    }

    #[test]
    fn or_set_tag_ordering() {
        let a = tag("a", 1);
        let b = tag("b", 1);
        assert!(a < b);
    }

    #[test]
    fn or_set_tag_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(tag("x", 1));
        set.insert(tag("x", 1));
        assert_eq!(set.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LwwEntry – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lww_entry_clone() {
        let entry = LwwEntry {
            value: 42,
            timestamp: 100,
            actor: actor("A"),
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn lww_entry_serde_roundtrip() {
        let entry = LwwEntry {
            value: "hello".to_string(),
            timestamp: 500,
            actor: actor("B"),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: LwwEntry<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LwwMap – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lww_map_serde_roundtrip() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("x".to_string(), 10, 100, actor("A"));
        map.insert("y".to_string(), 20, 200, actor("B"));

        let json = serde_json::to_string(&map).unwrap();
        let decoded: LwwMap<String, i32> = serde_json::from_str(&json).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn lww_map_get_nonexistent() {
        let map: LwwMap<String, i32> = LwwMap::default();
        assert!(map.get(&"missing".to_string()).is_none());
    }

    #[test]
    fn lww_map_same_timestamp_actor_tiebreak() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("k".to_string(), 1, 100, actor("aaa"));
        map.insert("k".to_string(), 2, 100, actor("zzz")); // zzz > aaa
        assert_eq!(map.get(&"k".to_string()).unwrap().value, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OrSet – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn or_set_serde_roundtrip() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("a".to_string(), tag("A", 1));
        set.add("b".to_string(), tag("A", 2));

        let json = serde_json::to_string(&set).unwrap();
        let decoded: OrSet<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(set, decoded);
    }

    #[test]
    fn or_set_is_empty_when_default() {
        let set: OrSet<String> = OrSet::default();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn or_set_is_empty_after_all_removed() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        set.remove_observed(&"x".to_string());
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.values().is_empty());
    }

    #[test]
    fn or_set_multiple_tags_same_value() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        set.add("x".to_string(), tag("B", 1));
        assert!(set.contains(&"x".to_string()));
        assert_eq!(set.len(), 1); // Still one value
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GCounter – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn gcounter_serde_roundtrip() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 10);
        counter.increment(actor("B"), 20);

        let json = serde_json::to_string(&counter).unwrap();
        let decoded: GCounter = serde_json::from_str(&json).unwrap();
        assert_eq!(counter, decoded);
    }

    #[test]
    fn gcounter_clone() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 5);
        let cloned = counter.clone();
        assert_eq!(counter, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PnCounter – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn pn_counter_serde_roundtrip() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 100);
        counter.decrement(actor("B"), 30);

        let json = serde_json::to_string(&counter).unwrap();
        let decoded: PnCounter = serde_json::from_str(&json).unwrap();
        assert_eq!(counter, decoded);
    }

    #[test]
    fn pn_counter_clone() {
        let mut counter = PnCounter::default();
        counter.increment(actor("X"), 50);
        counter.decrement(actor("Y"), 10);
        let cloned = counter.clone();
        assert_eq!(counter, cloned);
    }

    #[test]
    fn pn_counter_value_clamps_positive_overflow() {
        let mut counter = PnCounter::default();
        // Make positive extremely large
        counter.increment(actor("A"), u64::MAX);
        counter.increment(actor("B"), u64::MAX);
        // Value should clamp to i64::MAX
        let v = counter.value();
        assert_eq!(v, i64::MAX);
    }

    #[test]
    fn pn_counter_value_clamps_negative_overflow() {
        let mut counter = PnCounter::default();
        counter.decrement(actor("A"), u64::MAX);
        counter.decrement(actor("B"), u64::MAX);
        let v = counter.value();
        assert_eq!(v, i64::MIN);
    }

    #[test]
    fn pn_counter_large_values_precision() {
        let mut counter = PnCounter::default();
        // Increment by large amount > i64::MAX
        let huge = (i64::MAX as u64) + 1000;
        counter.increment(actor("A"), huge);

        // Decrement by large amount > i64::MAX
        let huge_less = huge - 5;
        counter.decrement(actor("B"), huge_less);

        // Old logic:
        // pos = i64::MAX (saturated)
        // neg = i64::MAX (saturated)
        // result = 0

        // New logic:
        // pos = huge
        // neg = huge - 5
        // diff = 5
        // result = 5

        assert_eq!(counter.value(), 5);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CrdtActorId – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn actor_id_empty_string() {
        let a = CrdtActorId::new("");
        assert_eq!(a.as_str(), "");
        assert_eq!(a.to_string(), "");
    }

    #[test]
    fn actor_id_unicode() {
        let a = CrdtActorId::new("node-\u{1F600}");
        assert_eq!(a.as_str(), "node-\u{1F600}");
    }

    #[test]
    fn actor_id_long_string() {
        let long = "a".repeat(10_000);
        let a = CrdtActorId::new(long.clone());
        assert_eq!(a.as_str(), long);
    }

    #[test]
    fn actor_id_debug_format() {
        let a = actor("dbg-node");
        let dbg = format!("{a:?}");
        assert!(dbg.contains("dbg-node"));
    }

    #[test]
    fn actor_id_as_ref_str() {
        let a = actor("ref-test");
        let s: &str = a.as_ref();
        assert_eq!(s, "ref-test");
    }

    #[test]
    fn actor_id_from_string_owned() {
        let s = String::from("owned");
        let a: CrdtActorId = s.into();
        assert_eq!(a.as_str(), "owned");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LwwEntry – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lww_entry_wins_over_much_higher_timestamp() {
        let new_entry = LwwEntry {
            value: "new",
            timestamp: u64::MAX,
            actor: actor("A"),
        };
        let old_entry = LwwEntry {
            value: "old",
            timestamp: 0,
            actor: actor("Z"),
        };
        assert!(new_entry.wins_over(&old_entry));
        assert!(!old_entry.wins_over(&new_entry));
    }

    #[test]
    fn lww_entry_tiebreak_with_equal_timestamp_equal_actor() {
        let a = LwwEntry {
            value: 1,
            timestamp: 100,
            actor: actor("same"),
        };
        let b = LwwEntry {
            value: 2,
            timestamp: 100,
            actor: actor("same"),
        };
        // Neither wins with equal timestamp and equal actor
        assert!(!a.wins_over(&b));
        assert!(!b.wins_over(&a));
    }

    #[test]
    fn lww_entry_debug_format() {
        let entry = LwwEntry {
            value: 42,
            timestamp: 100,
            actor: actor("A"),
        };
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("LwwEntry"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LwwMap – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lww_map_clone() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("k".to_string(), 42, 100, actor("A"));
        let cloned = map.clone();
        assert_eq!(map, cloned);
    }

    #[test]
    fn lww_map_many_keys() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        for i in 0..100 {
            map.insert(format!("key-{i}"), i, 100, actor("A"));
        }
        assert_eq!(map.len(), 100);
        assert!(!map.is_empty());
    }

    #[test]
    fn lww_map_overwrite_same_timestamp_lower_actor_ignored() {
        let mut map: LwwMap<String, i32> = LwwMap::default();
        map.insert("k".to_string(), 1, 100, actor("zzz"));
        map.insert("k".to_string(), 2, 100, actor("aaa")); // lower actor
        assert_eq!(map.get(&"k".to_string()).unwrap().value, 1);
    }

    #[test]
    fn lww_map_merge_multiple_keys_mixed() {
        let mut m1: LwwMap<String, i32> = LwwMap::default();
        m1.insert("a".to_string(), 1, 100, actor("X"));
        m1.insert("b".to_string(), 2, 200, actor("X"));

        let mut m2: LwwMap<String, i32> = LwwMap::default();
        m2.insert("a".to_string(), 10, 200, actor("Y"));
        m2.insert("b".to_string(), 20, 100, actor("Y"));
        m2.insert("c".to_string(), 30, 150, actor("Y"));

        m1.merge(&m2);
        assert_eq!(m1.get(&"a".to_string()).unwrap().value, 10); // m2 newer
        assert_eq!(m1.get(&"b".to_string()).unwrap().value, 2); // m1 newer
        assert_eq!(m1.get(&"c".to_string()).unwrap().value, 30); // only in m2
    }

    #[test]
    fn lww_map_merge_associative() {
        let mut a: LwwMap<String, i32> = LwwMap::default();
        a.insert("k".to_string(), 1, 100, actor("A"));

        let mut b: LwwMap<String, i32> = LwwMap::default();
        b.insert("k".to_string(), 2, 200, actor("B"));

        let mut c: LwwMap<String, i32> = LwwMap::default();
        c.insert("k".to_string(), 3, 300, actor("C"));

        // (a merge b) merge c
        let mut ab = a.clone();
        ab.merge(&b);
        ab.merge(&c);

        // a merge (b merge c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        assert_eq!(
            ab.get(&"k".to_string()).unwrap().value,
            a_bc.get(&"k".to_string()).unwrap().value
        );
    }

    #[test]
    fn lww_map_default_is_empty() {
        let map: LwwMap<String, String> = LwwMap::default();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn lww_map_insert_different_values_same_key_latest_wins() {
        let mut map: LwwMap<String, String> = LwwMap::default();
        map.insert("k".to_string(), "first".to_string(), 1, actor("A"));
        map.insert("k".to_string(), "second".to_string(), 2, actor("A"));
        map.insert("k".to_string(), "third".to_string(), 3, actor("A"));
        assert_eq!(map.get(&"k".to_string()).unwrap().value, "third");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OrSetTag – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn or_set_tag_clone() {
        let t = tag("a", 1);
        let cloned = t.clone();
        assert_eq!(t, cloned);
    }

    #[test]
    fn or_set_tag_debug_format() {
        let t = tag("actor1", 42);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("OrSetTag"));
        assert!(dbg.contains("actor1"));
    }

    #[test]
    fn or_set_tag_nonce_zero() {
        let t = tag("a", 0);
        assert_eq!(t.nonce, 0);
    }

    #[test]
    fn or_set_tag_nonce_max() {
        let t = tag("a", u64::MAX);
        assert_eq!(t.nonce, u64::MAX);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OrSet – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn or_set_clone() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        let cloned = set.clone();
        assert_eq!(set, cloned);
    }

    #[test]
    fn or_set_remove_nonexistent_is_noop() {
        let mut set: OrSet<String> = OrSet::default();
        set.remove_observed(&"missing".to_string());
        assert!(set.is_empty());
    }

    #[test]
    fn or_set_add_many_values() {
        let mut set: OrSet<u64> = OrSet::default();
        for i in 0u64..100 {
            set.add(i, OrSetTag::new(actor("A"), i));
        }
        assert_eq!(set.len(), 100);
    }

    #[test]
    fn or_set_values_sorted_for_btree() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("c".to_string(), tag("A", 3));
        set.add("a".to_string(), tag("A", 1));
        set.add("b".to_string(), tag("A", 2));
        // BTreeMap preserves order, so values should be sorted
        let vals = set.values();
        assert_eq!(vals, vec!["a", "b", "c"]);
    }

    #[test]
    fn or_set_merge_with_empty() {
        let mut set: OrSet<String> = OrSet::default();
        set.add("x".to_string(), tag("A", 1));
        let empty: OrSet<String> = OrSet::default();
        set.merge(&empty);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_empty_merge_into_nonempty() {
        let mut empty: OrSet<String> = OrSet::default();
        let mut nonempty: OrSet<String> = OrSet::default();
        nonempty.add("x".to_string(), tag("A", 1));
        empty.merge(&nonempty);
        assert_eq!(empty.len(), 1);
    }

    #[test]
    fn or_set_merge_associative() {
        let mut a: OrSet<String> = OrSet::default();
        a.add("x".to_string(), tag("A", 1));

        let mut b: OrSet<String> = OrSet::default();
        b.add("y".to_string(), tag("B", 1));

        let mut c: OrSet<String> = OrSet::default();
        c.add("z".to_string(), tag("C", 1));

        // (a merge b) merge c
        let mut ab = a.clone();
        ab.merge(&b);
        ab.merge(&c);

        // a merge (b merge c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        let mut vals_ab = ab.values();
        vals_ab.sort();
        let mut vals_abc = a_bc.values();
        vals_abc.sort();
        assert_eq!(vals_ab, vals_abc);
    }

    #[test]
    fn or_set_concurrent_remove_loses_to_concurrent_add() {
        // Standard OR-Set semantics: add wins over concurrent remove
        let mut replica1: OrSet<String> = OrSet::default();
        let mut replica2: OrSet<String> = OrSet::default();

        // Both start with "x" added by tag A:1
        replica1.add("x".to_string(), tag("A", 1));
        replica2.add("x".to_string(), tag("A", 1));

        // replica1 removes "x"
        replica1.remove_observed(&"x".to_string());

        // replica2 adds "x" with new tag
        replica2.add("x".to_string(), tag("B", 1));

        // Merge: B's add should survive
        replica1.merge(&replica2);
        assert!(replica1.contains(&"x".to_string()));
    }

    #[test]
    fn or_set_debug_format() {
        let set: OrSet<String> = OrSet::default();
        let dbg = format!("{set:?}");
        assert!(dbg.contains("OrSet"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GCounter – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn gcounter_increment_zero_delta() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 0);
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn gcounter_many_actors() {
        let mut counter = GCounter::default();
        for i in 0..100 {
            counter.increment(actor(&format!("actor-{i}")), 1);
        }
        assert_eq!(counter.value(), 100);
    }

    #[test]
    fn gcounter_merge_with_empty() {
        let mut counter = GCounter::default();
        counter.increment(actor("A"), 10);
        let empty = GCounter::default();
        counter.merge(&empty);
        assert_eq!(counter.value(), 10);
    }

    #[test]
    fn gcounter_empty_merge_into_nonempty() {
        let mut empty = GCounter::default();
        let mut nonempty = GCounter::default();
        nonempty.increment(actor("A"), 10);
        empty.merge(&nonempty);
        assert_eq!(empty.value(), 10);
    }

    #[test]
    fn gcounter_merge_associative() {
        let mut a = GCounter::default();
        a.increment(actor("A"), 5);

        let mut b = GCounter::default();
        b.increment(actor("B"), 10);

        let mut c = GCounter::default();
        c.increment(actor("C"), 15);

        let mut ab = a.clone();
        ab.merge(&b);
        ab.merge(&c);

        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        assert_eq!(ab.value(), a_bc.value());
    }

    #[test]
    fn gcounter_debug_format() {
        let counter = GCounter::default();
        let dbg = format!("{counter:?}");
        assert!(dbg.contains("GCounter"));
    }

    #[test]
    fn gcounter_default_counts_empty() {
        let counter = GCounter::default();
        assert!(counter.counts.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PnCounter – expanded coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn pn_counter_increment_then_decrement_to_zero() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 50);
        counter.decrement(actor("A"), 50);
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn pn_counter_many_actors() {
        let mut counter = PnCounter::default();
        for i in 0..50 {
            counter.increment(actor(&format!("inc-{i}")), 2);
        }
        for i in 0..30 {
            counter.decrement(actor(&format!("dec-{i}")), 1);
        }
        assert_eq!(counter.value(), 70); // 100 - 30
    }

    #[test]
    fn pn_counter_merge_with_empty() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 10);
        let empty = PnCounter::default();
        counter.merge(&empty);
        assert_eq!(counter.value(), 10);
    }

    #[test]
    fn pn_counter_merge_associative() {
        let mut a = PnCounter::default();
        a.increment(actor("A"), 5);

        let mut b = PnCounter::default();
        b.decrement(actor("B"), 3);

        let mut c = PnCounter::default();
        c.increment(actor("C"), 10);

        let mut ab = a.clone();
        ab.merge(&b);
        ab.merge(&c);

        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        assert_eq!(ab.value(), a_bc.value());
    }

    #[test]
    fn pn_counter_debug_format() {
        let counter = PnCounter::default();
        let dbg = format!("{counter:?}");
        assert!(dbg.contains("PnCounter"));
    }

    #[test]
    fn pn_counter_default_is_zero() {
        let counter = PnCounter::default();
        assert_eq!(counter.value(), 0);
        assert!(counter.positive.counts.is_empty());
        assert!(counter.negative.counts.is_empty());
    }

    #[test]
    fn pn_counter_only_decrements() {
        let mut counter = PnCounter::default();
        counter.decrement(actor("A"), 1);
        counter.decrement(actor("B"), 2);
        counter.decrement(actor("C"), 3);
        assert_eq!(counter.value(), -6);
    }

    #[test]
    fn pn_counter_increment_zero() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), 0);
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn pn_counter_decrement_zero() {
        let mut counter = PnCounter::default();
        counter.decrement(actor("A"), 0);
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn pn_counter_value_exactly_i64_max() {
        let mut counter = PnCounter::default();
        counter.increment(actor("A"), i64::MAX as u64);
        assert_eq!(counter.value(), i64::MAX);
    }
}
