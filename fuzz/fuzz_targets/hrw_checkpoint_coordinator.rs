#![no_main]

//! Fuzz target for HRW checkpoint coordinator selection
//! (checkpoint.rs:620-698).
//!
//! `hrw_hash_checkpoint`, `select_checkpoint_coordinator`, and
//! `rank_checkpoint_coordinators` form the NORMATIVE coordinator-
//! selection primitives. Highest Random Weight (HRW / Rendezvous)
//! hashing gives every node a deterministic priority for any
//! `(zone, epoch)` so peers converge on the same coordinator
//! without coordination — and so an adversary cannot bias the
//! selection by re-ordering input.
//!
//! NOT covered by any existing fuzz target.
//!
//! A regression that:
//!   - made `hrw_hash_checkpoint` non-deterministic would let two
//!     peers in the same zone disagree on the coordinator and
//!     stall epoch advancement.
//!   - dropped the length-prefix framing inside the hasher would
//!     allow `(zone="AB", epoch="CD")` and `(zone="ABCD", epoch="")`
//!     to map to the same hash, letting an attacker who controls
//!     the zone/epoch boundary bias the coordinator pick.
//!   - replaced max_by_key with min_by_key would silently flip
//!     selection to the LOWEST-priority node.
//!
//! Properties asserted:
//!
//!   1. **Determinism**: `hrw_hash_checkpoint` returns the same u64
//!      on repeated calls.
//!   2. **Length-prefix framing collision resistance**: building two
//!      `(zone, epoch, node)` triples with the same byte concatenation
//!      but different boundaries yields different hashes.
//!   3. **`select_checkpoint_coordinator`**: returns `None` iff the
//!      input slice is empty.
//!   4. **Argmax invariant**: when non-empty, the selected node has
//!      the maximum `hrw_hash_checkpoint` among all eligible nodes.
//!   5. **Selected ∈ eligible**: the selected node MUST appear in
//!      the eligible_nodes input.
//!   6. **`rank_checkpoint_coordinators` length**: `rank.len() ==
//!      eligible.len()`.
//!   7. **Rank descending by hash**: hashes of consecutive entries
//!      are non-increasing.
//!   8. **Rank head matches select**: `rank[0] ==
//!      select_checkpoint_coordinator(...).unwrap()` whenever
//!      eligible is non-empty.
//!   9. **Permutation invariant**: rank is a permutation of the
//!      eligible-nodes input as a multiset.
//!  10. **`select` and `rank` determinism** under repeated calls.
//!
//!   Once-gated anchors verify hand-picked rank ordering and the
//!   length-prefix framing collision-resistance case explicitly.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{
    EpochId, TailscaleNodeId, ZoneId, hrw_hash_checkpoint, rank_checkpoint_coordinators,
    select_checkpoint_coordinator,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Once;

static HRW_ANCHOR: Once = Once::new();

const ZONES: [&str; 5] = ["z:owner", "z:private", "z:work", "z:community", "z:public"];

#[derive(Arbitrary, Debug)]
struct Input {
    zone_disc: u8,
    epoch: String,
    node_ids: Vec<String>,
}

const MAX_NODES: usize = 16;
const MAX_EPOCH_LEN: usize = 64;
const MAX_NODE_LEN: usize = 64;

fn pick_zone(disc: u8) -> ZoneId {
    let z = ZONES[(disc as usize) % ZONES.len()];
    ZoneId::try_from(z.to_string()).expect("ZONES contains valid canonical ids")
}

fuzz_target!(|data: &[u8]| {
    HRW_ANCHOR.call_once(assert_hrw_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.epoch.len() > MAX_EPOCH_LEN
        || input.node_ids.len() > MAX_NODES
        || input.node_ids.iter().any(|n| n.len() > MAX_NODE_LEN)
    {
        return;
    }

    let zone = pick_zone(input.zone_disc);
    let epoch = EpochId::new(input.epoch);
    let nodes: Vec<TailscaleNodeId> = input
        .node_ids
        .iter()
        .map(|n| TailscaleNodeId::new(n.clone()))
        .collect();

    // ── PROPERTY 1: hrw_hash_checkpoint determinism ─────────────────────
    if let Some(first) = nodes.first() {
        let h_a = hrw_hash_checkpoint(&zone, &epoch, first);
        let h_b = hrw_hash_checkpoint(&zone, &epoch, first);
        assert_eq!(
            h_a, h_b,
            "hrw_hash_checkpoint non-deterministic for {first:?}"
        );
    }

    // ── PROPERTY 3: select returns None iff empty ───────────────────────
    let selected = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    if nodes.is_empty() {
        assert!(
            selected.is_none(),
            "select_checkpoint_coordinator returned Some for empty eligible_nodes"
        );
    } else {
        let s = selected.clone().expect("select on non-empty must be Some");

        // ── PROPERTY 4: argmax invariant ────────────────────────────────
        let s_hash = hrw_hash_checkpoint(&zone, &epoch, &s);
        for n in &nodes {
            let h = hrw_hash_checkpoint(&zone, &epoch, n);
            assert!(
                h <= s_hash,
                "select_checkpoint_coordinator picked {s:?} (hash={s_hash}) \
                 but {n:?} has higher hash {h}"
            );
        }

        // ── PROPERTY 5: selected ∈ eligible ────────────────────────────
        assert!(
            nodes.iter().any(|n| n.as_str() == s.as_str()),
            "selected node {s:?} not in eligible_nodes"
        );
    }

    // ── PROPERTY 6: rank length ────────────────────────────────────────
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
    assert_eq!(
        ranked.len(),
        nodes.len(),
        "rank_checkpoint_coordinators length mismatch"
    );

    // ── PROPERTY 7: rank descending by hash ─────────────────────────────
    for w in ranked.windows(2) {
        let h0 = hrw_hash_checkpoint(&zone, &epoch, &w[0]);
        let h1 = hrw_hash_checkpoint(&zone, &epoch, &w[1]);
        assert!(
            h0 >= h1,
            "rank not descending by hash: {:?} hash={h0} preceded {:?} hash={h1}",
            w[0],
            w[1]
        );
    }

    // ── PROPERTY 8: rank head == select ─────────────────────────────────
    if let Some(s) = selected.as_ref() {
        let head = ranked.first().expect("non-empty rank head");
        assert_eq!(
            head.as_str(),
            s.as_str(),
            "rank[0] != select_checkpoint_coordinator"
        );
    }

    // ── PROPERTY 9: permutation invariant ──────────────────────────────
    let mut input_counts: HashMap<&str, usize> = HashMap::new();
    for n in &nodes {
        *input_counts.entry(n.as_str()).or_insert(0) += 1;
    }
    let mut rank_counts: HashMap<&str, usize> = HashMap::new();
    for n in &ranked {
        *rank_counts.entry(n.as_str()).or_insert(0) += 1;
    }
    assert_eq!(
        input_counts, rank_counts,
        "rank is not a multiset-permutation of eligible_nodes"
    );

    // ── PROPERTY 10: select/rank determinism ───────────────────────────
    let selected2 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    let ranked2 = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
    assert_eq!(
        selected.map(|n| n.as_str().to_string()),
        selected2.map(|n| n.as_str().to_string()),
        "select non-deterministic"
    );
    let ranked_strs: Vec<String> = ranked.iter().map(|n| n.as_str().to_string()).collect();
    let ranked2_strs: Vec<String> = ranked2.iter().map(|n| n.as_str().to_string()).collect();
    assert_eq!(ranked_strs, ranked2_strs, "rank non-deterministic");

    // ── PROPERTY 2: framing collision resistance ───────────────────────
    // Build two triples (z, e, n) and (z', e', n') such that
    // z_bytes || e_bytes || n_bytes is the same byte sequence, but the
    // boundaries differ. The length-prefix framing in
    // hrw_hash_checkpoint MUST give them distinct hashes.
    let z1 = ZoneId::try_from("z:work".to_string()).expect("known zone");
    let e1 = EpochId::new("zone-suffix");
    let n1 = TailscaleNodeId::new("node-1");

    let z2 = ZoneId::try_from("z:work".to_string()).expect("known zone");
    let e2 = EpochId::new("zone-suffixnode-1");
    let n2 = TailscaleNodeId::new("");

    // The concatenation (without length prefixes) of (z1, e1, n1) and
    // (z2, e2, n2) is identical: z:work || zone-suffix || node-1 ==
    // z:work || zone-suffixnode-1 || "". Length-prefix framing must
    // separate them.
    let h_a = hrw_hash_checkpoint(&z1, &e1, &n1);
    let h_b = hrw_hash_checkpoint(&z2, &e2, &n2);
    assert_ne!(
        h_a, h_b,
        "hrw_hash_checkpoint collided across boundary split — \
         length-prefix framing in framed input is broken; an attacker \
         who controls zone/epoch/node-id boundaries can bias coordinator \
         pick"
    );
});

/// Once-gated anchors: hand-picked rank ordering, framing collision-
/// resistance, and select/rank consistency on a known input.
fn assert_hrw_anchored() {
    let zone = ZoneId::work();
    let epoch = EpochId::new("anchor-epoch");
    let nodes: Vec<TailscaleNodeId> = (0..5)
        .map(|i| TailscaleNodeId::new(format!("node-{i}")))
        .collect();

    // (a) select returns None on empty input.
    assert!(
        select_checkpoint_coordinator(&zone, &epoch, &[]).is_none(),
        "ANCHOR REGRESSION: select on empty must be None"
    );
    let r_empty = rank_checkpoint_coordinators(&zone, &epoch, &[]);
    assert!(r_empty.is_empty(), "ANCHOR: rank on empty must be empty");

    // (b) Determinism on non-empty input.
    let s1 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    let s2 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    assert_eq!(
        s1.as_ref().map(|n| n.as_str().to_owned()),
        s2.as_ref().map(|n| n.as_str().to_owned()),
        "ANCHOR REGRESSION: select non-deterministic"
    );

    // (c) Argmax invariant: re-derive winner manually.
    let s = s1.expect("ANCHOR: select on 5 nodes must be Some");
    let s_hash = hrw_hash_checkpoint(&zone, &epoch, &s);
    for n in &nodes {
        let h = hrw_hash_checkpoint(&zone, &epoch, n);
        assert!(
            h <= s_hash,
            "ANCHOR REGRESSION: select did not return the argmax — {n:?} has higher hash"
        );
    }

    // (d) Rank head == select.
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
    assert_eq!(ranked.len(), nodes.len(), "ANCHOR: rank length");
    assert_eq!(
        ranked[0].as_str(),
        s.as_str(),
        "ANCHOR REGRESSION: rank[0] != select"
    );
    // Rank descending by hash.
    for w in ranked.windows(2) {
        let h0 = hrw_hash_checkpoint(&zone, &epoch, &w[0]);
        let h1 = hrw_hash_checkpoint(&zone, &epoch, &w[1]);
        assert!(h0 >= h1, "ANCHOR REGRESSION: rank not descending");
    }

    // (e) Length-prefix framing collision resistance.
    let z1 = ZoneId::try_from("z:work".to_string()).unwrap();
    let e1 = EpochId::new("E1");
    let n1 = TailscaleNodeId::new("NODE1");
    let z2 = ZoneId::try_from("z:work".to_string()).unwrap();
    let e2 = EpochId::new("E1NODE1");
    let n2 = TailscaleNodeId::new("");
    let h_a = hrw_hash_checkpoint(&z1, &e1, &n1);
    let h_b = hrw_hash_checkpoint(&z2, &e2, &n2);
    assert_ne!(
        h_a, h_b,
        "ANCHOR REGRESSION: hrw_hash_checkpoint collides across boundary split — \
         length-prefix framing in framed inputs is broken"
    );
}
