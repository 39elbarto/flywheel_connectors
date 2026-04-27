#![no_main]

//! State-machine fuzz target for `fcp_core::pcs::PcsGroupState`
//! (pcs.rs:138-410).
//!
//! `PcsGroupState` is the TreeKEM-inspired group key agreement for
//! sensitive zones (z:owner, z:private). Post-compromise security
//! (PCS) requires that:
//!   - advance_epoch produces a NEW zone_key distinct from the previous
//!   - remove_member advances the epoch + invalidates the removed
//!     member's ability to derive future keys
//!
//! A regression that broke the epoch ratchet (advance_epoch reuses a
//! previous secret, or remove_member fails to ratchet) would let a
//! compromised member continue to read post-removal traffic — the
//! exact attack PCS is designed to prevent.
//!
//! NOT covered by existing fuzz.
//!
//! Properties asserted:
//!
//!   1. **Constructor validation**: empty/oversized/duplicate inputs
//!      MUST be rejected with the documented error variants.
//!   2. **member_count agreement**: member_count() == members().len().
//!   3. **is_member completeness**: every constructed member returns
//!      is_member=true; a non-member returns false.
//!   4. **derive_zone_key determinism**: same state ⇒ same key.
//!   5. **advance_epoch ratchet**: epoch increments by 1 AND zone_key
//!      changes (post-compromise security).
//!   6. **remove_member effects**: epoch advances, member_count
//!      decreases, removed node is no longer a member.
//!   7. **add_member effects**: epoch advances, member_count
//!      increases, added node is a member.
//!
//!   Once-gated regression anchors:
//!     (a) Empty group → EmptyGroup.
//!     (b) PCS_MAX_GROUP_SIZE+1 → GroupTooLarge with correct counts.
//!     (c) Duplicate node_id → DuplicateMember.
//!     (d) advance_epoch from epoch=0 produces a zone_key distinct
//!         from epoch=0's zone_key (the load-bearing PCS invariant).

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::TailscaleNodeId;
use fcp_core::pcs::{GroupMember, PCS_MAX_GROUP_SIZE, PcsError, PcsGroupState};
use fcp_core::{ZoneId, ZoneKey};
use fcp_crypto::X25519SecretKey;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const X25519_SK_SIZE: usize = 32;

static PCS_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Bounded so we don't exceed PCS_MAX_GROUP_SIZE on the happy path.
    member_count_seed: u8,
    initial_secret: [u8; 32],
    member_seed: u8,
    /// Whether to advance the epoch.
    do_advance: bool,
    /// Whether to remove a member.
    do_remove: bool,
    /// Whether to add a member.
    do_add: bool,
}

fn make_member(idx: u32, seed: u8) -> GroupMember {
    let sk = X25519SecretKey::from_bytes([seed.wrapping_add(idx as u8); X25519_SK_SIZE]);
    GroupMember {
        node_id: TailscaleNodeId::new(format!("node-{idx}")),
        public_key: sk.public_key(),
        leaf_index: idx,
    }
}

fn zone_keys_equal(a: &ZoneKey, b: &ZoneKey) -> bool {
    a.as_bytes() == b.as_bytes()
}

fuzz_target!(|data: &[u8]| {
    PCS_ANCHOR.call_once(assert_pcs_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Bound to a small, valid range. PCS_MAX_GROUP_SIZE is 32; we cap
    // at 8 for fuzz speed.
    let n = ((input.member_count_seed as u32) % 8) + 1;
    let members: Vec<GroupMember> = (0..n).map(|i| make_member(i, input.member_seed)).collect();

    let zone = ZoneId::work();
    let mut state = match PcsGroupState::new(zone.clone(), members.clone(), input.initial_secret) {
        Ok(s) => s,
        Err(_) => return,
    };

    // ── PROPERTY 2: member_count agreement ────────────────────────────
    assert_eq!(
        state.member_count(),
        state.members().len(),
        "member_count != members().len()"
    );
    assert_eq!(
        state.member_count(),
        n as usize,
        "member_count != input length"
    );

    // ── PROPERTY 3: is_member completeness ───────────────────────────
    for m in &members {
        assert!(
            state.is_member(&m.node_id),
            "is_member returned false for constructed member {:?}",
            m.node_id
        );
    }
    let stranger = TailscaleNodeId::new("not-a-member");
    if !members
        .iter()
        .any(|m| m.node_id.as_str() == stranger.as_str())
    {
        assert!(
            !state.is_member(&stranger),
            "is_member returned true for non-member"
        );
    }

    // ── PROPERTY 4: derive_zone_key determinism ──────────────────────
    let key_a = state.derive_zone_key().expect("derive_zone_key");
    let key_b = state.derive_zone_key().expect("derive_zone_key 2");
    assert!(
        zone_keys_equal(&key_a, &key_b),
        "derive_zone_key not deterministic on the same state"
    );

    // ── PROPERTY 5: advance_epoch ratchet ────────────────────────────
    if input.do_advance {
        let pre_epoch = state.current_epoch();
        let pre_key = state.derive_zone_key().expect("pre-advance key");

        let result = state.advance_epoch().expect("advance_epoch");
        assert_eq!(
            result.previous_epoch, pre_epoch,
            "advance_epoch.previous_epoch wrong"
        );
        assert_eq!(
            result.new_epoch,
            pre_epoch + 1,
            "advance_epoch did not increment by 1"
        );
        assert_eq!(
            state.current_epoch(),
            pre_epoch + 1,
            "current_epoch doesn't reflect advance"
        );

        let post_key = state.derive_zone_key().expect("post-advance key");
        assert!(
            !zone_keys_equal(&pre_key, &post_key),
            "advance_epoch produced the SAME zone_key — post-compromise \
             security broken; a compromised peer would continue to read \
             post-rekey traffic"
        );
    }

    // ── PROPERTY 6: remove_member effects ────────────────────────────
    if input.do_remove && state.member_count() > 1 {
        let target = members[0].node_id.clone();
        let pre_epoch = state.current_epoch();
        let pre_count = state.member_count();
        state.remove_member(&target).expect("remove_member");

        assert_eq!(
            state.member_count(),
            pre_count - 1,
            "remove_member did not decrease count"
        );
        assert!(
            !state.is_member(&target),
            "remove_member: removed node still reports is_member=true"
        );
        assert_eq!(
            state.current_epoch(),
            pre_epoch + 1,
            "remove_member did not advance epoch (PCS rekey)"
        );
    }

    // ── PROPERTY 7: add_member effects ───────────────────────────────
    if input.do_add && state.member_count() < PCS_MAX_GROUP_SIZE {
        let new_member = make_member(9999, input.member_seed.wrapping_add(0xCD));
        if !state.is_member(&new_member.node_id) {
            let pre_epoch = state.current_epoch();
            let pre_count = state.member_count();
            state.add_member(new_member.clone()).expect("add_member");

            assert_eq!(
                state.member_count(),
                pre_count + 1,
                "add_member did not increase count"
            );
            assert!(
                state.is_member(&new_member.node_id),
                "add_member: new node not a member"
            );
            // Per the docstring: "Adding a member does NOT invalidate
            // the current epoch secret — forward secrecy is maintained
            // because the new member cannot derive past epoch secrets."
            // We still expect the epoch to advance (the implementation
            // does so for audit purposes).
            assert!(
                state.current_epoch() > pre_epoch,
                "add_member did not advance epoch"
            );
        }
    }
});

/// Once-gated regression anchors for the most load-bearing PCS
/// invariants.
fn assert_pcs_anchored() {
    let zone = ZoneId::work();
    let secret = [0x42u8; 32];

    // (a) Empty group → EmptyGroup.
    match PcsGroupState::new(zone.clone(), vec![], secret) {
        Err(PcsError::EmptyGroup) => {}
        other => {
            panic!("ANCHOR REGRESSION: empty group new() returned {other:?}; expected EmptyGroup")
        }
    }

    // (b) PCS_MAX_GROUP_SIZE+1 → GroupTooLarge.
    let oversized: Vec<GroupMember> = (0..=PCS_MAX_GROUP_SIZE as u32)
        .map(|i| make_member(i, 0x11))
        .collect();
    match PcsGroupState::new(zone.clone(), oversized, secret) {
        Err(PcsError::GroupTooLarge { size, max }) => {
            assert_eq!(
                size,
                PCS_MAX_GROUP_SIZE + 1,
                "ANCHOR: GroupTooLarge.size wrong"
            );
            assert_eq!(max, PCS_MAX_GROUP_SIZE, "ANCHOR: GroupTooLarge.max wrong");
        }
        other => panic!(
            "ANCHOR REGRESSION: oversized group new() returned {other:?}; expected GroupTooLarge"
        ),
    }

    // (c) Duplicate node_id → DuplicateMember.
    let m1 = make_member(0, 0x22);
    let mut m2 = make_member(1, 0x33);
    m2.node_id = m1.node_id.clone(); // force duplicate
    match PcsGroupState::new(zone.clone(), vec![m1.clone(), m2], secret) {
        Err(PcsError::DuplicateMember(s)) => {
            assert_eq!(
                s,
                m1.node_id.as_str(),
                "ANCHOR: DuplicateMember reported wrong node_id"
            );
        }
        other => panic!(
            "ANCHOR REGRESSION: duplicate-member new() returned {other:?}; expected DuplicateMember"
        ),
    }

    // (d) advance_epoch produces a NEW zone_key — load-bearing PCS
    // invariant.
    let members = vec![make_member(0, 0x77), make_member(1, 0x88)];
    let mut state = PcsGroupState::new(zone, members, secret).expect("anchor state");
    let pre = state.derive_zone_key().expect("anchor pre-key");
    state.advance_epoch().expect("anchor advance");
    let post = state.derive_zone_key().expect("anchor post-key");
    assert!(
        !zone_keys_equal(&pre, &post),
        "ANCHOR REGRESSION: advance_epoch produced an identical zone_key — \
         the epoch ratchet at pcs.rs:260-279 has degraded; post-compromise \
         security is broken; a compromised peer continues to read \
         post-rekey traffic."
    );
}
