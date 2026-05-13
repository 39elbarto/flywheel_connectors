//! Compact quotient-style fingerprint filter.
//!
//! The filter stores a fixed-width fingerprint in an open-addressed quotient
//! table. It is intended as a negative cache in front of exact stores: `false`
//! means "definitely absent" for inserted keys that have not been deleted,
//! while `true` still requires exact verification by the caller.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

const EMPTY: u64 = 0;
const TOMBSTONE: u64 = 1;
const MIN_SLOTS: usize = 16;
const MAX_LOAD_NUMERATOR: usize = 7;
const MAX_LOAD_DENOMINATOR: usize = 8;

/// Approximate membership filter with deletion support.
///
/// The table stores 64-bit remainders in quotient-selected slots. At the
/// configured load factor, a miss scans a short cluster and therefore has an
/// expected false-positive rate far below `2^-16`, while the heap footprint is
/// eight bytes per slot.
#[derive(Debug, Clone)]
pub struct QuotientFilter<T> {
    slots: Vec<u64>,
    items: usize,
    tombstones: usize,
    _item: PhantomData<fn() -> T>,
}

impl<T> Default for QuotientFilter<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> QuotientFilter<T> {
    /// Create an empty filter without allocating slots.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            items: 0,
            tombstones: 0,
            _item: PhantomData,
        }
    }

    /// Create a filter sized for `expected_items`.
    #[must_use]
    pub fn with_capacity(expected_items: usize) -> Self {
        let slot_count = Self::slots_for_items(expected_items);
        Self {
            slots: vec![EMPTY; slot_count],
            items: 0,
            tombstones: 0,
            _item: PhantomData,
        }
    }

    /// Number of live fingerprints in the filter.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items
    }

    /// Whether the filter contains no live fingerprints.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items == 0
    }

    /// Number of slots currently allocated.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Heap bytes used by the slot table.
    #[must_use]
    pub fn heap_size_bytes(&self) -> usize {
        self.slots.capacity() * std::mem::size_of::<u64>()
    }

    /// Remove every live fingerprint while keeping allocated slots for reuse.
    pub fn clear(&mut self) {
        self.slots.fill(EMPTY);
        self.items = 0;
        self.tombstones = 0;
    }

    fn slots_for_items(items: usize) -> usize {
        if items == 0 {
            return 0;
        }

        items
            .saturating_mul(MAX_LOAD_DENOMINATOR)
            .div_ceil(MAX_LOAD_NUMERATOR)
            .max(MIN_SLOTS)
    }

    const fn max_live_items(slot_count: usize) -> usize {
        slot_count.saturating_mul(MAX_LOAD_NUMERATOR) / MAX_LOAD_DENOMINATOR
    }

    fn needs_growth(&self) -> bool {
        self.slots.is_empty()
            || self.items.saturating_add(self.tombstones).saturating_add(1)
                > Self::max_live_items(self.slots.len())
    }

    fn fingerprint<Q: Hash + ?Sized>(item: &Q) -> u64 {
        let mut remainder_hasher = DefaultHasher::new();
        0x9e37_79b9_7f4a_7c15_u64.hash(&mut remainder_hasher);
        item.hash(&mut remainder_hasher);

        let mut remainder = remainder_hasher.finish();
        if remainder <= TOMBSTONE {
            remainder = remainder.wrapping_add(2);
        }
        remainder
    }

    fn index_for(remainder: u64, slot_count: usize) -> usize {
        if slot_count == 0 {
            return 0;
        }
        let slot_count_u64 = u64::try_from(slot_count).unwrap_or(u64::MAX);
        let index = remainder % slot_count_u64;
        usize::try_from(index).unwrap_or(0)
    }

    const fn next_index(index: usize, slot_count: usize) -> usize {
        if index + 1 == slot_count {
            0
        } else {
            index + 1
        }
    }

    fn find_remainder(&self, remainder: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }

        let mut index = Self::index_for(remainder, self.slots.len());
        for _ in 0..self.slots.len() {
            match self.slots[index] {
                EMPTY => return None,
                value if value == remainder => return Some(index),
                _ => index = Self::next_index(index, self.slots.len()),
            }
        }
        None
    }

    fn insert_remainder(&mut self, remainder: u64) -> bool {
        let mut index = Self::index_for(remainder, self.slots.len());
        let mut first_tombstone = None;

        for _ in 0..self.slots.len() {
            match self.slots[index] {
                EMPTY => {
                    let target = first_tombstone.unwrap_or(index);
                    if self.slots[target] == TOMBSTONE {
                        self.tombstones = self.tombstones.saturating_sub(1);
                    }
                    self.slots[target] = remainder;
                    self.items += 1;
                    return true;
                }
                TOMBSTONE => {
                    first_tombstone.get_or_insert(index);
                    index = Self::next_index(index, self.slots.len());
                }
                value if value == remainder => return false,
                _ => index = Self::next_index(index, self.slots.len()),
            }
        }

        if let Some(target) = first_tombstone {
            self.slots[target] = remainder;
            self.items += 1;
            self.tombstones = self.tombstones.saturating_sub(1);
            true
        } else {
            false
        }
    }

    fn rehash(&mut self, new_slot_count: usize) {
        if new_slot_count == 0 {
            self.slots.clear();
            self.items = 0;
            self.tombstones = 0;
            return;
        }

        let old_slots = std::mem::replace(&mut self.slots, vec![EMPTY; new_slot_count]);
        self.items = 0;
        self.tombstones = 0;

        for remainder in old_slots {
            if remainder > TOMBSTONE {
                self.insert_remainder(remainder);
            }
        }
    }
}

impl<T: Hash> QuotientFilter<T> {
    /// Insert `item` into the filter.
    ///
    /// Returns `true` when the filter changed and `false` when an equivalent
    /// fingerprint was already present.
    pub fn insert(&mut self, item: &T) -> bool {
        let remainder = Self::fingerprint(item);

        if self.needs_growth() {
            let slot_count = Self::slots_for_items(self.items.saturating_add(1));
            self.rehash(slot_count);
        }

        if self.find_remainder(remainder).is_some() {
            return false;
        }

        self.insert_remainder(remainder)
    }

    /// Return whether `item` may be present in the filter.
    #[must_use]
    pub fn may_contain(&self, item: &T) -> bool {
        self.find_remainder(Self::fingerprint(item)).is_some()
    }

    /// Alias for [`Self::may_contain`].
    #[must_use]
    pub fn contains(&self, item: &T) -> bool {
        self.may_contain(item)
    }

    /// Delete `item` from the filter.
    ///
    /// Returns `true` when a matching fingerprint was removed. As with other
    /// fingerprint filters, callers should only delete keys they inserted.
    pub fn delete(&mut self, item: &T) -> bool {
        let remainder = Self::fingerprint(item);
        let Some(index) = self.find_remainder(remainder) else {
            return false;
        };

        self.slots[index] = TOMBSTONE;
        self.items = self.items.saturating_sub(1);
        self.tombstones += 1;

        if self.items == 0 {
            self.clear();
        } else if self.tombstones > self.items {
            let slot_count = Self::slots_for_items(self.items);
            self.rehash(slot_count);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::QuotientFilter;

    #[test]
    fn insert_lookup_delete_round_trip() {
        let mut filter = QuotientFilter::with_capacity(16);

        assert!(filter.insert(&42_u64));
        assert!(filter.may_contain(&42_u64));
        assert!(!filter.may_contain(&43_u64));
        assert!(filter.delete(&42_u64));
        assert!(!filter.may_contain(&42_u64));
    }

    #[test]
    fn clear_retains_capacity_but_removes_membership() {
        let mut filter = QuotientFilter::with_capacity(128);
        let slots = filter.slot_count();

        for value in 0_u64..64 {
            filter.insert(&value);
        }
        filter.clear();

        assert_eq!(filter.slot_count(), slots);
        assert!(filter.is_empty());
        assert!(!filter.may_contain(&1_u64));
    }
}
