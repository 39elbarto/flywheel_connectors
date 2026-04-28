#![no_main]

//! Fuzz target for `RevocationRegistry::add_revocation` dominance,
//! `update_head` monotonicity, `is_revoked` / `is_revoked_at`,
//! `is_fresh` / `check_freshness`, and `RevocationObject::is_active`
//! (revocation.rs:128-660).
//!
//! `add_revocation` implements the C1 fix preventing past-expiry
//! suppression — incoming revocations may only replace existing ones
//! when they STRICTLY DOMINATE in the (effective_at↓, expires_at↑)
//! poset. NOT covered as a discrete unit by any existing fuzz target.
//!
//! A regression that:
//!   - dropped the dominance check would let a far-future-effective_at
//!     revocation overwrite a currently-active one (defer-attack).
//!   - dropped the strict-monotonic guard in `update_head` would let
//!     an attacker replay an old head pointer and mask later revocations.
//!   - flipped the `Strict` freshness gate would let stale data pass
//!     a critical-tier check.
//!
//! Properties asserted:
//!
//!   1. **`is_active` time gate**: `now < effective_at` → false; `None`
//!      expires_at means active forever after effective_at; `Some(exp)`
//!      means active in `[effective_at, exp)`.
//!   2. **`revokes` membership**: `revokes(id)` iff `id ∈ revoked`.
//!   3. **`is_revoked` HashMap agreement**: `is_revoked(id)` iff a
//!      revocation was added for `id`.
//!   4. **`add_revocation` dominance**: never-expires (`None`) replaces
//!      finite expiry; same start with later expiry replaces; same
//!      start with earlier expiry does NOT replace; later
//!      `effective_at` NEVER replaces (defer attack).
//!   5. **`update_head` monotonic**: `seq <= head_seq` with existing
//!      head is rejected.
//!   6. **`is_fresh`**: returns `head_seq >= remote_seq`.
//!   7. **`check_freshness` Strict**: `allowed = is_fresh`.
//!   8. **`check_freshness` Warn**: `allowed = is_fresh ||
//!      within_max_age`.
//!   9. **`check_freshness` BestEffort**: always `allowed = true`.
//!
//!   Once-gated anchors verify the C1 attack defenses + freshness
//!   policy matrix on hand-picked inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_core::{
    FreshnessFailureReason, FreshnessPolicy, ObjectHeader, ObjectId, Provenance, RevocationObject,
    RevocationRegistry, RevocationScope, ZoneId,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static REVOCATION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    object_id_bytes: [u8; 32],
    other_object_id_bytes: [u8; 32],
    effective_at_existing: u64,
    expires_at_existing: Option<u64>,
    effective_at_new: u64,
    expires_at_new: Option<u64>,
    now: u64,
    /// FreshnessPolicy discriminant (mod 3).
    policy_disc: u8,
    head_seq_a: u64,
    head_seq_b: u64,
    remote_seq: u64,
    max_age_secs: u64,
    last_updated: u64,
}

fn make_revocation(
    object_id: ObjectId,
    effective_at: u64,
    expires_at: Option<u64>,
) -> RevocationObject {
    RevocationObject {
        header: ObjectHeader {
            schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        revoked: vec![object_id],
        scope: RevocationScope::Capability,
        reason: "fuzz".into(),
        effective_at,
        expires_at,
        signature: [0u8; 64],
    }
}

fn pick_policy(disc: u8) -> FreshnessPolicy {
    match disc % 3 {
        0 => FreshnessPolicy::Strict,
        1 => FreshnessPolicy::Warn,
        _ => FreshnessPolicy::BestEffort,
    }
}

fuzz_target!(|data: &[u8]| {
    REVOCATION_ANCHOR.call_once(assert_revocation_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let oid = ObjectId::from_bytes(input.object_id_bytes);
    let other_oid = ObjectId::from_bytes(input.other_object_id_bytes);

    // ── PROPERTY 1: is_active time gate ─────────────────────────────────
    let rev = make_revocation(oid, input.effective_at_existing, input.expires_at_existing);
    let active = rev.is_active(input.now);
    let expected_active = input.now >= input.effective_at_existing
        && input.expires_at_existing.is_none_or(|exp| input.now < exp);
    assert_eq!(
        active, expected_active,
        "is_active({}) on (effective={}, expires={:?}) returned {active}; expected {expected_active}",
        input.now, input.effective_at_existing, input.expires_at_existing
    );

    // ── PROPERTY 2: revokes membership ──────────────────────────────────
    assert!(
        rev.revokes(&oid),
        "revokes() must return true for the included id"
    );
    assert!(
        !rev.revokes(&other_oid) || other_oid == oid,
        "revokes() returned true for non-included id"
    );

    // ── PROPERTY 3: is_revoked HashMap agreement ────────────────────────
    let mut reg = RevocationRegistry::new();
    assert!(
        !reg.is_revoked(&oid),
        "fresh registry must not have any revocations"
    );
    reg.add_revocation(&rev);
    assert!(
        reg.is_revoked(&oid),
        "registry should have id after add_revocation"
    );
    assert_eq!(reg.len(), 1, "registry len after one add must be 1");

    // ── PROPERTY 4: add_revocation dominance ────────────────────────────
    let new_rev = make_revocation(oid, input.effective_at_new, input.expires_at_new);
    reg.add_revocation(&new_rev);

    let stored = reg.get_revocation(&oid).expect("registry lost the entry");

    let dominates = compute_dominance(
        input.effective_at_existing,
        input.expires_at_existing,
        input.effective_at_new,
        input.expires_at_new,
    );
    if dominates {
        assert_eq!(
            stored.effective_at, input.effective_at_new,
            "dominant new should have replaced (effective_at)"
        );
        assert_eq!(
            stored.expires_at, input.expires_at_new,
            "dominant new should have replaced (expires_at)"
        );
    } else {
        assert_eq!(
            stored.effective_at, input.effective_at_existing,
            "non-dominant new must NOT replace (effective_at) — defer / suppression attack"
        );
        assert_eq!(
            stored.expires_at, input.expires_at_existing,
            "non-dominant new must NOT replace (expires_at)"
        );
    }

    // ── PROPERTY 5: update_head monotonicity ────────────────────────────
    let mut reg2 = RevocationRegistry::new();
    let head_a = ObjectId::from_bytes([0x11u8; 32]);
    let head_b = ObjectId::from_bytes([0x22u8; 32]);
    reg2.update_head(head_a, input.head_seq_a, input.last_updated);
    let after_a_seq = reg2.head_seq;
    let after_a_head = reg2.head;
    assert_eq!(after_a_seq, input.head_seq_a);
    assert_eq!(after_a_head, Some(head_a));

    reg2.update_head(head_b, input.head_seq_b, input.last_updated);
    if input.head_seq_b > input.head_seq_a {
        assert_eq!(reg2.head_seq, input.head_seq_b);
        assert_eq!(reg2.head, Some(head_b));
    } else {
        assert_eq!(
            reg2.head_seq, input.head_seq_a,
            "update_head accepted seq <= head_seq — monotonicity broken"
        );
        assert_eq!(reg2.head, Some(head_a));
    }

    // ── PROPERTY 6 + 7 + 8 + 9: freshness policy matrix ─────────────────
    reg2.last_updated = input.last_updated;
    let policy = pick_policy(input.policy_disc);
    let result = reg2.check_freshness(input.remote_seq, policy, input.max_age_secs, input.now);
    let is_fresh = reg2.head_seq >= input.remote_seq;
    let age = input.now.saturating_sub(input.last_updated);
    let within_max_age = age <= input.max_age_secs;

    assert_eq!(reg2.is_fresh(input.remote_seq), is_fresh);

    match policy {
        FreshnessPolicy::Strict => {
            assert_eq!(result.allowed, is_fresh, "Strict.allowed != is_fresh");
            if is_fresh {
                assert!(result.reason.is_none(), "Strict fresh must have no reason");
            } else {
                assert!(matches!(
                    result.reason,
                    Some(FreshnessFailureReason::StaleData)
                ));
            }
        }
        FreshnessPolicy::Warn => {
            assert_eq!(
                result.allowed,
                is_fresh || within_max_age,
                "Warn.allowed != (is_fresh || within_max_age)"
            );
            if is_fresh {
                assert!(result.reason.is_none(), "Warn fresh must have no reason");
            } else if within_max_age {
                assert!(matches!(
                    result.reason,
                    Some(FreshnessFailureReason::StaleButWithinMaxAge)
                ));
            } else {
                assert!(matches!(
                    result.reason,
                    Some(FreshnessFailureReason::StaleData)
                ));
            }
        }
        FreshnessPolicy::BestEffort => {
            assert!(result.allowed, "BestEffort.allowed must always be true");
            if is_fresh {
                assert!(
                    result.reason.is_none(),
                    "BestEffort fresh must have no reason"
                );
            } else {
                assert!(matches!(
                    result.reason,
                    Some(FreshnessFailureReason::StaleButAllowed)
                ));
            }
        }
    }
});

/// Reference dominance check: when does `new` strictly dominate `existing`?
fn compute_dominance(
    existing_eff: u64,
    existing_exp: Option<u64>,
    new_eff: u64,
    new_exp: Option<u64>,
) -> bool {
    let starts_no_later = new_eff <= existing_eff;
    let ends_no_sooner = match (new_exp, existing_exp) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(n), Some(e)) => n >= e,
    };
    let ends_strictly_later = match (new_exp, existing_exp) {
        (None, Some(_)) => true,
        (Some(n), Some(e)) => n > e,
        _ => false,
    };
    let starts_strictly_earlier = new_eff < existing_eff;
    starts_no_later && ends_no_sooner && (starts_strictly_earlier || ends_strictly_later)
}

/// Once-gated anchors: C1 attack defenses + freshness matrix.
fn assert_revocation_anchored() {
    let oid = ObjectId::from_bytes([0xAAu8; 32]);

    // (a) Defer attack: existing eff=10, exp=None. New eff=100, exp=None
    // does NOT dominate (later effective_at). Existing must remain.
    let mut reg = RevocationRegistry::new();
    let existing = make_revocation(oid, 10, None);
    let later_start = make_revocation(oid, 100, None);
    reg.add_revocation(&existing);
    reg.add_revocation(&later_start);
    let stored = reg.get_revocation(&oid).expect("ANCHOR: stored");
    assert_eq!(
        stored.effective_at, 10,
        "ANCHOR REGRESSION: defer attack succeeded — later effective_at replaced"
    );

    // (b) Past-expiry suppression: existing eff=10, exp=None. New eff=10,
    // exp=Some(20) does NOT dominate (earlier expiry). Existing must remain.
    let mut reg = RevocationRegistry::new();
    let existing = make_revocation(oid, 10, None);
    let bounded = make_revocation(oid, 10, Some(20));
    reg.add_revocation(&existing);
    reg.add_revocation(&bounded);
    let stored = reg.get_revocation(&oid).expect("ANCHOR");
    assert_eq!(
        stored.expires_at, None,
        "ANCHOR REGRESSION: past-expiry suppression — bounded replaced unbounded"
    );

    // (c) Same start, later expiry → replaces.
    let mut reg = RevocationRegistry::new();
    let bounded_short = make_revocation(oid, 10, Some(20));
    let bounded_long = make_revocation(oid, 10, Some(50));
    reg.add_revocation(&bounded_short);
    reg.add_revocation(&bounded_long);
    let stored = reg.get_revocation(&oid).expect("ANCHOR");
    assert_eq!(
        stored.expires_at,
        Some(50),
        "ANCHOR: same start with later expiry should replace"
    );

    // (d) Tightening to permanent (None > finite).
    let mut reg = RevocationRegistry::new();
    let bounded = make_revocation(oid, 10, Some(20));
    let permanent = make_revocation(oid, 10, None);
    reg.add_revocation(&bounded);
    reg.add_revocation(&permanent);
    let stored = reg.get_revocation(&oid).expect("ANCHOR");
    assert_eq!(
        stored.expires_at, None,
        "ANCHOR: same start tightened to permanent should replace"
    );

    // (e) update_head monotonicity.
    let mut reg = RevocationRegistry::new();
    reg.update_head(ObjectId::from_bytes([1u8; 32]), 5, 100);
    assert_eq!(reg.head_seq, 5);
    reg.update_head(ObjectId::from_bytes([2u8; 32]), 3, 200);
    assert_eq!(
        reg.head_seq, 5,
        "ANCHOR REGRESSION: update_head accepted seq=3 after seq=5"
    );
    assert_eq!(reg.head, Some(ObjectId::from_bytes([1u8; 32])));
    reg.update_head(ObjectId::from_bytes([3u8; 32]), 10, 300);
    assert_eq!(reg.head_seq, 10);
    assert_eq!(reg.head, Some(ObjectId::from_bytes([3u8; 32])));

    // (f) is_active time gate hand-picked.
    let r = make_revocation(oid, 100, Some(200));
    assert!(!r.is_active(50), "ANCHOR: before effective_at not active");
    assert!(r.is_active(100), "ANCHOR: at effective_at active");
    assert!(r.is_active(150), "ANCHOR: in window active");
    assert!(!r.is_active(200), "ANCHOR: at expires_at not active");
    assert!(!r.is_active(300), "ANCHOR: after expires_at not active");

    // (g) Freshness matrix — fresh.
    let mut reg = RevocationRegistry::new();
    reg.update_head(ObjectId::from_bytes([1u8; 32]), 10, 1000);
    let fresh = reg.check_freshness(5, FreshnessPolicy::Strict, 60, 1010);
    assert!(fresh.allowed && !fresh.stale && fresh.reason.is_none());

    // (h) Freshness matrix — Strict, stale.
    let stale = reg.check_freshness(20, FreshnessPolicy::Strict, 60, 1010);
    assert!(!stale.allowed && stale.stale);
    assert!(matches!(
        stale.reason,
        Some(FreshnessFailureReason::StaleData)
    ));

    // (i) Freshness matrix — Warn within max_age.
    let warn_within = reg.check_freshness(20, FreshnessPolicy::Warn, 60, 1030);
    assert!(warn_within.allowed && warn_within.stale);
    assert!(matches!(
        warn_within.reason,
        Some(FreshnessFailureReason::StaleButWithinMaxAge)
    ));

    // (j) Freshness matrix — Warn beyond max_age.
    let warn_beyond = reg.check_freshness(20, FreshnessPolicy::Warn, 5, 1030);
    assert!(!warn_beyond.allowed);
    assert!(matches!(
        warn_beyond.reason,
        Some(FreshnessFailureReason::StaleData)
    ));

    // (k) Freshness matrix — BestEffort always allowed.
    let best = reg.check_freshness(20, FreshnessPolicy::BestEffort, 0, 99999);
    assert!(best.allowed);
    assert!(matches!(
        best.reason,
        Some(FreshnessFailureReason::StaleButAllowed)
    ));
}
