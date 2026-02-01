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
                Some(existing) if existing.wins_over(entry) || existing == entry => {}
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
}
