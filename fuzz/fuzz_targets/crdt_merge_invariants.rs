#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{CrdtActorId, GCounter, LwwMap, OrSet, OrSetTag, PnCounter};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_OPS: usize = 128;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Replica {
    Left,
    Right,
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
        Replica::Left => 0,
        Replica::Right => 1,
    }
}

fn assert_merge_converges<T>(left: &T, right: &T)
where
    T: Clone + PartialEq + core::fmt::Debug,
    T: Merge,
{
    let mut left_then_right = left.clone();
    left_then_right.merge_from(right);

    let mut right_then_left = right.clone();
    right_then_left.merge_from(left);

    assert_eq!(
        left_then_right, right_then_left,
        "CRDT merge must converge regardless of merge order"
    );

    let before_idempotent = left_then_right.clone();
    left_then_right.merge_from(&before_idempotent.clone());
    assert_eq!(
        left_then_right, before_idempotent,
        "CRDT merge must be idempotent"
    );
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

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let mut lww = [LwwMap::<String, i16>::default(), LwwMap::default()];
    let mut or_set = [OrSet::<String>::default(), OrSet::default()];
    let mut g_counter = [GCounter::default(), GCounter::default()];
    let mut pn_counter = [PnCounter::default(), PnCounter::default()];

    for op in input.ops.into_iter().take(MAX_OPS) {
        match op {
            Op::Lww {
                replica,
                key,
                value,
                timestamp,
                actor: actor_id,
            } => {
                lww[map_for(replica)].insert(
                    format!("key-{key:02x}"),
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
                g_counter[map_for(replica)].increment(actor(actor_id), u64::from(delta));
            }
            Op::PnCounter {
                replica,
                actor: actor_id,
                delta,
                decrement,
            } => {
                let counter = &mut pn_counter[map_for(replica)];
                if decrement {
                    counter.decrement(actor(actor_id), u64::from(delta));
                } else {
                    counter.increment(actor(actor_id), u64::from(delta));
                }
            }
        }
    }

    assert_merge_converges(&lww[0], &lww[1]);
    assert_merge_converges(&or_set[0], &or_set[1]);
    assert_merge_converges(&g_counter[0], &g_counter[1]);
    assert_merge_converges(&pn_counter[0], &pn_counter[1]);
});
