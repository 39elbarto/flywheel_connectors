#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{CrdtActorId, GCounter, LwwMap, OrSet, OrSetTag, PnCounter};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_OPS: usize = 128;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Replica {
    A,
    B,
    C,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Lww {
        replica: Replica,
        key: u8,
        value: i16,
        timestamp: u16,
        actor: u8,
    },
    OrAdd {
        replica: Replica,
        value: u8,
        actor: u8,
        nonce: u16,
    },
    OrRemove {
        replica: Replica,
        value: u8,
    },
    GCounter {
        replica: Replica,
        actor: u8,
        delta: u16,
    },
    PnCounter {
        replica: Replica,
        actor: u8,
        delta: u16,
        decrement: bool,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    ops: Vec<Op>,
}

fn actor(id: u8) -> CrdtActorId {
    CrdtActorId::new(format!("actor-{id:02x}"))
}

fn map_for(replica: Replica) -> usize {
    match replica {
        Replica::A => 0,
        Replica::B => 1,
        Replica::C => 2,
    }
}

fn merged_in_order<T>(replicas: [&T; 3], order: [usize; 3]) -> T
where
    T: Clone,
    T: Merge,
{
    let mut merged = replicas[order[0]].clone();
    merged.merge_from(replicas[order[1]]);
    merged.merge_from(replicas[order[2]]);
    merged
}

fn assert_merge_invariants<T>(replicas: [&T; 3], label: &str)
where
    T: Clone + PartialEq + core::fmt::Debug,
    T: Merge,
{
    let mut ab = replicas[0].clone();
    ab.merge_from(replicas[1]);

    let mut ba = replicas[1].clone();
    ba.merge_from(replicas[0]);
    assert_eq!(ab, ba, "{label}: merge must be commutative for every pair");

    let mut idempotent = ab.clone();
    idempotent.merge_from(&ab.clone());
    assert_eq!(idempotent, ab, "{label}: merge must be idempotent");

    let mut left_associated = replicas[0].clone();
    left_associated.merge_from(replicas[1]);
    left_associated.merge_from(replicas[2]);

    let mut bc = replicas[1].clone();
    bc.merge_from(replicas[2]);
    let mut right_associated = replicas[0].clone();
    right_associated.merge_from(&bc);
    assert_eq!(
        left_associated, right_associated,
        "{label}: merge must be associative"
    );

    let canonical = merged_in_order(replicas, [0, 1, 2]);
    for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        assert_eq!(
            merged_in_order(replicas, order),
            canonical,
            "{label}: merge result must not depend on replica ordering"
        );
    }
}

trait Merge {
    fn merge_from(&mut self, other: &Self);
}

impl<K, V> Merge for LwwMap<K, V>
where
    K: Ord + Clone,
    V: Clone + PartialEq,
{
    fn merge_from(&mut self, other: &Self) {
        self.merge(other);
    }
}

impl<T> Merge for OrSet<T>
where
    T: Ord + Clone,
{
    fn merge_from(&mut self, other: &Self) {
        self.merge(other);
    }
}

impl Merge for GCounter {
    fn merge_from(&mut self, other: &Self) {
        self.merge(other);
    }
}

impl Merge for PnCounter {
    fn merge_from(&mut self, other: &Self) {
        self.merge(other);
    }
}

fn assert_lww_monotonic_insert(
    map: &mut LwwMap<String, i16>,
    key: String,
    value: i16,
    timestamp: u64,
    actor_id: CrdtActorId,
) {
    let before = map.get(&key).map(|entry| entry.timestamp);
    map.insert(key.clone(), value, timestamp, actor_id);
    let after = map.get(&key).map(|entry| entry.timestamp);

    if let (Some(before), Some(after)) = (before, after) {
        assert!(
            after >= before,
            "LwwMap winning timestamp must never move backwards"
        );
    }
}

fn assert_gcounter_monotonic_increment(counter: &mut GCounter, actor_id: CrdtActorId, delta: u64) {
    let before = counter.value();
    counter.increment(actor_id, delta);
    assert!(
        counter.value() >= before,
        "GCounter value must be monotonic after increment"
    );
}

fn assert_pncounter_monotonic_component(
    counter: &mut PnCounter,
    actor_id: CrdtActorId,
    delta: u64,
    decrement: bool,
) {
    if decrement {
        let before = counter.negative.value();
        counter.decrement(actor_id, delta);
        assert!(
            counter.negative.value() >= before,
            "PnCounter negative component must be monotonic after decrement"
        );
    } else {
        let before = counter.positive.value();
        counter.increment(actor_id, delta);
        assert!(
            counter.positive.value() >= before,
            "PnCounter positive component must be monotonic after increment"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let mut lww = [
        LwwMap::<String, i16>::default(),
        LwwMap::default(),
        LwwMap::default(),
    ];
    let mut or_set = [
        OrSet::<String>::default(),
        OrSet::default(),
        OrSet::default(),
    ];
    let mut g_counter = [
        GCounter::default(),
        GCounter::default(),
        GCounter::default(),
    ];
    let mut pn_counter = [
        PnCounter::default(),
        PnCounter::default(),
        PnCounter::default(),
    ];
    let mut lww_keys = BTreeSet::new();

    for op in input.ops.into_iter().take(MAX_OPS) {
        match op {
            Op::Lww {
                replica,
                key,
                value,
                timestamp,
                actor: actor_id,
            } => {
                let key = format!("key-{key:02x}");
                lww_keys.insert(key.clone());
                assert_lww_monotonic_insert(
                    &mut lww[map_for(replica)],
                    key,
                    value,
                    u64::from(timestamp),
                    actor(actor_id),
                );
            }
            Op::OrAdd {
                replica,
                value,
                actor: actor_id,
                nonce,
            } => {
                or_set[map_for(replica)].add(
                    format!("value-{value:02x}"),
                    OrSetTag::new(actor(actor_id), u64::from(nonce)),
                );
            }
            Op::OrRemove { replica, value } => {
                or_set[map_for(replica)].remove_observed(&format!("value-{value:02x}"));
            }
            Op::GCounter {
                replica,
                actor: actor_id,
                delta,
            } => {
                assert_gcounter_monotonic_increment(
                    &mut g_counter[map_for(replica)],
                    actor(actor_id),
                    u64::from(delta),
                );
            }
            Op::PnCounter {
                replica,
                actor: actor_id,
                delta,
                decrement,
            } => {
                assert_pncounter_monotonic_component(
                    &mut pn_counter[map_for(replica)],
                    actor(actor_id),
                    u64::from(delta),
                    decrement,
                );
            }
        }
    }

    assert_merge_invariants([&lww[0], &lww[1], &lww[2]], "LwwMap");
    assert_merge_invariants([&or_set[0], &or_set[1], &or_set[2]], "OrSet");
    assert_merge_invariants([&g_counter[0], &g_counter[1], &g_counter[2]], "GCounter");
    assert_merge_invariants(
        [&pn_counter[0], &pn_counter[1], &pn_counter[2]],
        "PnCounter",
    );

    let merged_lww = merged_in_order([&lww[0], &lww[1], &lww[2]], [0, 1, 2]);
    for key in lww_keys {
        let merged_timestamp = merged_lww
            .get(&key)
            .map(|entry| entry.timestamp)
            .unwrap_or_default();
        for replica in &lww {
            if let Some(entry) = replica.get(&key) {
                assert!(
                    merged_timestamp >= entry.timestamp,
                    "LwwMap merged timestamp must dominate every replica version"
                );
            }
        }
    }
});
