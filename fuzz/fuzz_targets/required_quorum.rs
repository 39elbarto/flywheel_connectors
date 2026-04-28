#![no_main]

//! Fuzz target for `fcp_core::required_quorum` and the `QuorumPolicy`
//! / `SignatureSet` quorum primitives (quorum.rs:179-444).
//!
//! These are the NORMATIVE Byzantine-quorum sizing rules and the
//! signature-set canonicalization that protect zone-checkpoint and
//! capability-issuance signing chains. NOT covered as a discrete unit
//! by any existing fuzz target.
//!
//! A regression that:
//!   - flipped Risky from f+1 to f would let a single faulty node
//!     achieve quorum on its own.
//!   - allowed `can_proceed_degraded` to admit Dangerous tiers under
//!     degraded mode would let a partition advance critical writes
//!     without full BFT quorum.
//!   - dropped the duplicate-node check in `SignatureSet::add` would
//!     let a single node signature be counted twice toward a quorum.
//!
//! Properties asserted:
//!
//!   1. **`required_quorum` tier values**: `Safe → 1`, `Risky → f+1`,
//!      `Dangerous → n-f`, `CriticalWrite → n-f`.
//!   2. **Dangerous == CriticalWrite** at the function level.
//!   3. **Monotonicity in tier strength**:
//!      `Safe ≤ Risky ≤ Dangerous = CriticalWrite`.
//!   4. **Result ≤ n**: never asks for more signatures than exist.
//!   5. **`QuorumPolicy::required_signatures` agrees with
//!      `required_quorum`**.
//!   6. **`is_quorum_met(count, tier)` ⇔ `count >=
//!      required_signatures(tier)`**.
//!   7. **`can_proceed_degraded`**: false when degraded mode disabled,
//!      false when `available < degraded_mode_min_nodes`, true only
//!      for Safe tier when degraded mode is enabled and the floor is
//!      met.
//!   8. **`SignatureSet::add` deduplication**: returns `true` for a
//!      fresh node_id and `false` for a duplicate; len follows.
//!   9. **`SignatureSet` sorted by `node_id` post-add**.
//!  10. **`satisfies_quorum` agrees with `is_quorum_met(len(), tier)`**.
//!  11. **`canonical_bytes` deterministic**: same set yields same bytes.
//!
//!   Once-gated anchors verify each tier value, the equality of
//!   Dangerous/CriticalWrite, and the SignatureSet dedup + sort
//!   invariants on hand-picked inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{
    NodeId, NodeSignature, QuorumPolicy, RiskTier, SignatureSet, ZoneId, required_quorum,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static QUORUM_ANCHOR: Once = Once::new();

const MAX_SIGS: usize = 16;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Eligible node count (clamped to 1..=64).
    n_raw: u8,
    /// Max faults (clamped to 0..n).
    f_raw: u8,
    /// Tier discriminant (mod 4).
    tier_disc: u8,
    /// Available nodes for degraded-mode test (mod n+1).
    available_raw: u8,
    /// Whether degraded mode is enabled.
    degraded_enabled: bool,
    /// Min nodes for degraded mode (mod n+1).
    degraded_min: u8,
    /// Node IDs for SignatureSet (string, may include duplicates).
    sig_node_ids: Vec<String>,
    /// signed_at timestamps.
    sig_times: Vec<u64>,
}

fn pick_tier(disc: u8) -> RiskTier {
    match disc % 4 {
        0 => RiskTier::Safe,
        1 => RiskTier::Risky,
        2 => RiskTier::Dangerous,
        _ => RiskTier::CriticalWrite,
    }
}

fuzz_target!(|data: &[u8]| {
    QUORUM_ANCHOR.call_once(assert_quorum_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.sig_node_ids.len() > MAX_SIGS || input.sig_node_ids.iter().any(|s| s.len() > 64) {
        return;
    }

    // Clamp n into [1, 64] and f into [0, n-1].
    let n = (u32::from(input.n_raw) % 64) + 1;
    let f = u32::from(input.f_raw) % n;
    let tier = pick_tier(input.tier_disc);

    // ── PROPERTY 1: required_quorum tier values ─────────────────────────
    let req = required_quorum(n, f, tier);
    let expected_req = match tier {
        RiskTier::Safe => 1,
        RiskTier::Risky => f + 1,
        RiskTier::Dangerous | RiskTier::CriticalWrite => n - f,
    };
    assert_eq!(
        req, expected_req,
        "required_quorum(n={n}, f={f}, {tier:?}) = {req}; expected {expected_req}"
    );

    // ── PROPERTY 2: Dangerous == CriticalWrite ──────────────────────────
    assert_eq!(
        required_quorum(n, f, RiskTier::Dangerous),
        required_quorum(n, f, RiskTier::CriticalWrite),
        "Dangerous and CriticalWrite quorum sizes differ"
    );

    // ── PROPERTY 3: tier monotonicity ───────────────────────────────────
    let safe = required_quorum(n, f, RiskTier::Safe);
    let risky = required_quorum(n, f, RiskTier::Risky);
    let dangerous = required_quorum(n, f, RiskTier::Dangerous);
    assert!(
        safe <= risky,
        "Safe ({safe}) > Risky ({risky}) at (n={n},f={f})"
    );
    assert!(
        risky <= dangerous,
        "Risky ({risky}) > Dangerous ({dangerous}) at (n={n},f={f})"
    );

    // ── PROPERTY 4: result ≤ n ──────────────────────────────────────────
    assert!(req <= n, "required_quorum returned {req} > n={n}");

    // ── PROPERTY 5: QuorumPolicy::required_signatures agreement ─────────
    let policy = QuorumPolicy::new(ZoneId::work(), n, f);
    let policy_req = policy.required_signatures(tier);
    assert_eq!(
        policy_req, req,
        "QuorumPolicy::required_signatures diverges from required_quorum"
    );

    // ── PROPERTY 6: is_quorum_met agreement ─────────────────────────────
    for count in [0u32, 1, req.saturating_sub(1), req, req + 1, n] {
        let met = policy.is_quorum_met(count, tier);
        assert_eq!(
            met,
            count >= req,
            "is_quorum_met(count={count}, {tier:?}) disagrees with count >= {req}"
        );
    }

    // ── PROPERTY 7: can_proceed_degraded ────────────────────────────────
    let policy_no_degraded = QuorumPolicy::new(ZoneId::work(), n, f);
    let available = u32::from(input.available_raw) % (n + 1);
    assert!(
        !policy_no_degraded.can_proceed_degraded(available, tier),
        "can_proceed_degraded returned true with degraded mode disabled"
    );

    if input.degraded_enabled {
        let min_nodes = u32::from(input.degraded_min) % (n + 1);
        let policy_d = QuorumPolicy::new(ZoneId::work(), n, f).with_degraded_mode(min_nodes);
        let result = policy_d.can_proceed_degraded(available, tier);
        let expected = available >= min_nodes && tier == RiskTier::Safe;
        assert_eq!(
            result, expected,
            "can_proceed_degraded(available={available}, {tier:?}) on min={min_nodes} \
             returned {result}; expected {expected}"
        );
    }

    // ── PROPERTY 8 + 9: SignatureSet add dedup + sort ───────────────────
    let mut set = SignatureSet::new();
    let mut seen = std::collections::HashSet::new();
    for (i, id_str) in input.sig_node_ids.iter().enumerate() {
        let nid = NodeId::new(id_str.clone());
        let signed_at = input.sig_times.get(i).copied().unwrap_or(0);
        let sig = NodeSignature::new(nid.clone(), [0u8; 64], signed_at);
        let len_before = set.len();
        let added = set.add(sig);
        let is_new = seen.insert(id_str.clone());
        assert_eq!(
            added, is_new,
            "SignatureSet::add returned {added} for node_id={id_str:?}; expected {is_new} \
             (set already had this id: {})",
            !is_new
        );
        if added {
            assert_eq!(
                set.len(),
                len_before + 1,
                "SignatureSet::add returned true but len did not grow"
            );
        } else {
            assert_eq!(
                set.len(),
                len_before,
                "SignatureSet::add returned false but len changed"
            );
        }
    }
    // Sorted by node_id post-add.
    let slice = set.as_slice();
    for w in slice.windows(2) {
        assert!(
            w[0].node_id.as_str() <= w[1].node_id.as_str(),
            "SignatureSet not sorted by node_id"
        );
    }

    // ── PROPERTY 10: satisfies_quorum agreement ─────────────────────────
    let count = u32::try_from(set.len()).unwrap_or(u32::MAX);
    assert_eq!(
        set.satisfies_quorum(&policy, tier),
        policy.is_quorum_met(count, tier),
        "satisfies_quorum disagrees with is_quorum_met(len, tier)"
    );

    // ── PROPERTY 11: canonical_bytes deterministic ──────────────────────
    let bytes_a = set.canonical_bytes();
    let bytes_b = set.canonical_bytes();
    assert_eq!(bytes_a, bytes_b, "canonical_bytes non-deterministic");
});

/// Once-gated anchors: each tier value, Dangerous/CriticalWrite
/// equality, dedup + sort invariants.
fn assert_quorum_anchored() {
    // (a) Tier values at (n=4, f=1).
    assert_eq!(required_quorum(4, 1, RiskTier::Safe), 1);
    assert_eq!(required_quorum(4, 1, RiskTier::Risky), 2);
    assert_eq!(required_quorum(4, 1, RiskTier::Dangerous), 3);
    assert_eq!(required_quorum(4, 1, RiskTier::CriticalWrite), 3);

    // (b) Dangerous == CriticalWrite at multiple (n, f).
    for n in [1u32, 2, 4, 7, 16] {
        for f in 0..n {
            assert_eq!(
                required_quorum(n, f, RiskTier::Dangerous),
                required_quorum(n, f, RiskTier::CriticalWrite),
                "ANCHOR REGRESSION: Dangerous != CriticalWrite at (n={n}, f={f})"
            );
        }
    }

    // (c) Monotonicity at (n=7, f=2).
    assert!(
        required_quorum(7, 2, RiskTier::Safe) <= required_quorum(7, 2, RiskTier::Risky)
            && required_quorum(7, 2, RiskTier::Risky) <= required_quorum(7, 2, RiskTier::Dangerous),
        "ANCHOR REGRESSION: tier monotonicity broken"
    );

    // (d) QuorumPolicy::required_signatures agreement.
    let policy = QuorumPolicy::new(ZoneId::work(), 4, 1);
    assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
    assert_eq!(policy.required_signatures(RiskTier::Risky), 2);
    assert_eq!(policy.required_signatures(RiskTier::Dangerous), 3);
    assert_eq!(policy.required_signatures(RiskTier::CriticalWrite), 3);

    // (e) is_quorum_met boundary.
    assert!(!policy.is_quorum_met(2, RiskTier::Dangerous));
    assert!(policy.is_quorum_met(3, RiskTier::Dangerous));
    assert!(policy.is_quorum_met(4, RiskTier::Dangerous));

    // (f) can_proceed_degraded matrix.
    let no_degraded = QuorumPolicy::new(ZoneId::work(), 4, 1);
    assert!(!no_degraded.can_proceed_degraded(4, RiskTier::Safe));
    assert!(!no_degraded.can_proceed_degraded(2, RiskTier::Risky));
    let with_degraded = QuorumPolicy::new(ZoneId::work(), 4, 1).with_degraded_mode(2);
    assert!(
        with_degraded.can_proceed_degraded(2, RiskTier::Safe),
        "ANCHOR: degraded mode + Safe + available >= min must allow"
    );
    assert!(
        !with_degraded.can_proceed_degraded(1, RiskTier::Safe),
        "ANCHOR: available below min must reject"
    );
    assert!(
        !with_degraded.can_proceed_degraded(2, RiskTier::Risky),
        "ANCHOR REGRESSION: degraded mode allowed Risky tier"
    );
    assert!(
        !with_degraded.can_proceed_degraded(2, RiskTier::Dangerous),
        "ANCHOR REGRESSION: degraded mode allowed Dangerous tier"
    );

    // (g) SignatureSet dedup + sort.
    let mut set = SignatureSet::new();
    assert!(set.add(NodeSignature::new(NodeId::new("charlie"), [0u8; 64], 0)));
    assert!(set.add(NodeSignature::new(NodeId::new("alice"), [0u8; 64], 0)));
    assert!(set.add(NodeSignature::new(NodeId::new("bob"), [0u8; 64], 0)));
    // Duplicate.
    assert!(
        !set.add(NodeSignature::new(NodeId::new("alice"), [1u8; 64], 1)),
        "ANCHOR REGRESSION: duplicate node_id was admitted"
    );
    assert_eq!(set.len(), 3);
    let slice = set.as_slice();
    assert_eq!(slice[0].node_id.as_str(), "alice");
    assert_eq!(slice[1].node_id.as_str(), "bob");
    assert_eq!(slice[2].node_id.as_str(), "charlie");

    // (h) canonical_bytes deterministic.
    let a = set.canonical_bytes();
    let b = set.canonical_bytes();
    assert_eq!(a, b, "ANCHOR REGRESSION: canonical_bytes non-deterministic");
}
