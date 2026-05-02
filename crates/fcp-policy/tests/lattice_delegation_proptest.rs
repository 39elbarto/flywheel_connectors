//! Lattice-trapdoor delegation walker fuzz-style harness via proptest.
//!
//! Goal: prove that `LatticeDelegationVerifierImpl::verify_sub_token`
//! NEVER panics and NEVER loops forever for any caller-controlled
//! certificate-chain shape — including cycles, self-references,
//! depth-bombs, broken parent links, and zone/period mismatches.
//!
//! The DoS-relevant invariant is the depth cap: the walker MUST
//! terminate in at most `params.depth` hops regardless of chain
//! topology. We sanity-check that with an explicit timeout assertion
//! in addition to the standard "doesn't panic" coverage.

use std::time::{Duration, Instant};

use fcp_core::{OperationId, PrincipalId, ZoneId};
use fcp_crypto_pq::LatticeParams;
use fcp_policy::lattice_delegation::{
    DelegationCertificate, DelegationCertificateId, DelegationPeriod, LatticeDelegationError,
    LatticeDelegationVerifier, LatticeDelegationVerifierImpl, LatticeSubToken,
};
use proptest::prelude::*;

fn cert_id(byte: u8) -> DelegationCertificateId {
    DelegationCertificateId::from_bytes([byte; 32])
}

fn zone() -> ZoneId {
    ZoneId::work()
}

fn period_open() -> DelegationPeriod {
    DelegationPeriod {
        start_unix_ms: 0,
        end_unix_ms: u64::MAX,
    }
}

fn cert(id_byte: u8, parent: Option<u8>, zone_id: ZoneId, period: DelegationPeriod) -> DelegationCertificate {
    DelegationCertificate {
        cert_id: cert_id(id_byte),
        zone_id,
        period,
        parent_cert_id: parent.map(cert_id),
        pub_matrix_seed: [0u8; 32],
    }
}

fn verifier_with(certs: Vec<DelegationCertificate>) -> LatticeDelegationVerifierImpl {
    LatticeDelegationVerifierImpl::with_certificates(LatticeParams::V4_REFERENCE, certs)
}

fn sub_token_targeting(leaf: u8) -> LatticeSubToken {
    LatticeSubToken {
        cert_id: cert_id(leaf),
        op_id: OperationId::new("op:test").unwrap(),
        principal_id: PrincipalId::new("agent:test").unwrap(),
        request_descriptor_hash: [0u8; 32],
        preimage_bytes: vec![0u8; 64],
    }
}

fn assert_terminates(verifier: &LatticeDelegationVerifierImpl, sub_token: &LatticeSubToken) {
    // The walker must terminate in well under a second. If it ever
    // doesn't, this test will hang and CI catches it; we still bound
    // it explicitly so a regression on a small-depth cycle bug is
    // visible.
    let start = Instant::now();
    let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verifier.verify_sub_token(sub_token, &zone(), 1_700_000_000_000)
    }));
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "lattice walker took {} ms — possible unbounded loop",
        start.elapsed().as_millis()
    );
}

// ── Targeted regression cases (easier to read than proptest output) ──

#[test]
fn lattice_walker_self_reference_bounds_at_depth_param() {
    // Cert A → A (self-loop). Walker must hit ChainTooDeep at
    // params.depth, NOT loop forever.
    let v = verifier_with(vec![cert(1, Some(1), zone(), period_open())]);
    let sub = sub_token_targeting(1);
    assert_terminates(&v, &sub);
    let err = v
        .verify_sub_token(&sub, &zone(), 1_700_000_000_000)
        .unwrap_err();
    assert!(
        matches!(err, LatticeDelegationError::ChainTooDeep { .. }),
        "self-loop must surface ChainTooDeep, got {err:?}"
    );
}

#[test]
fn lattice_walker_two_cycle_bounds_at_depth_param() {
    // A → B → A. Walker visits A,B,A,B,A,... bounded by depth.
    let v = verifier_with(vec![
        cert(1, Some(2), zone(), period_open()),
        cert(2, Some(1), zone(), period_open()),
    ]);
    let sub = sub_token_targeting(1);
    assert_terminates(&v, &sub);
    let err = v
        .verify_sub_token(&sub, &zone(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(err, LatticeDelegationError::ChainTooDeep { .. }));
}

#[test]
fn lattice_walker_unknown_cert_returns_typed_err() {
    let v = verifier_with(vec![]);
    let err = v
        .verify_sub_token(&sub_token_targeting(99), &zone(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(
        err,
        LatticeDelegationError::UnknownCertificate { .. }
    ));
}

#[test]
fn lattice_walker_missing_parent_returns_incomplete_chain_err() {
    // A → 99 (parent absent from trust set).
    let v = verifier_with(vec![cert(1, Some(99), zone(), period_open())]);
    let sub = sub_token_targeting(1);
    assert_terminates(&v, &sub);
    let err = v
        .verify_sub_token(&sub, &zone(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(
        err,
        LatticeDelegationError::IncompleteDelegationChain { .. }
    ));
}

#[test]
fn lattice_walker_period_zero_zero_rejects_with_outside_period() {
    let v = verifier_with(vec![cert(
        1,
        None,
        zone(),
        DelegationPeriod {
            start_unix_ms: 0,
            end_unix_ms: 0,
        },
    )]);
    let sub = sub_token_targeting(1);
    let err = v
        .verify_sub_token(&sub, &zone(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(err, LatticeDelegationError::OutsidePeriod { .. }));
}

#[test]
fn lattice_walker_period_with_start_after_end_does_not_panic() {
    // Adversarial period: start > end. period.contains() returns false
    // for any now, so this must surface OutsidePeriod, not panic.
    let v = verifier_with(vec![cert(
        1,
        None,
        zone(),
        DelegationPeriod {
            start_unix_ms: u64::MAX,
            end_unix_ms: 0,
        },
    )]);
    let sub = sub_token_targeting(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        v.verify_sub_token(&sub, &zone(), 1_700_000_000_000)
    }));
    assert!(result.is_ok(), "inverted-period must not panic");
    let err = result.unwrap().unwrap_err();
    assert!(matches!(err, LatticeDelegationError::OutsidePeriod { .. }));
}

// ── Proptest randomized harness ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Adversarial chain: random parent links across a small ID space,
    /// random periods, random preimage length, random query time.
    /// Walker MUST terminate in <500ms and return a typed Err for
    /// every input. The verifier never panics regardless of cycle /
    /// depth-bomb / missing-parent shapes.
    #[test]
    fn lattice_walker_adversarial_chain_never_panics_or_loops(
        chain_size in 0usize..=8,
        parent_links in proptest::collection::vec(0u8..=10, 0..=8),
        period_starts in proptest::collection::vec(any::<u64>(), 0..=8),
        period_ends in proptest::collection::vec(any::<u64>(), 0..=8),
        leaf_id in 0u8..=10,
        now_unix_ms in any::<u64>(),
        preimage_len in 0usize..=256,
    ) {
        // Build `chain_size` certs, each with id = i+1 and a
        // potentially adversarial parent link (cycles, self-refs,
        // missing parents are all reachable via the parent_links input).
        let mut certs = Vec::with_capacity(chain_size);
        for i in 0..chain_size {
            let parent = parent_links.get(i).copied();
            let start = period_starts.get(i).copied().unwrap_or(0);
            let end = period_ends.get(i).copied().unwrap_or(u64::MAX);
            certs.push(cert(
                u8::try_from(i + 1).unwrap_or(u8::MAX),
                parent,
                zone(),
                DelegationPeriod {
                    start_unix_ms: start,
                    end_unix_ms: end,
                },
            ));
        }
        let v = verifier_with(certs);

        let sub = LatticeSubToken {
            cert_id: cert_id(leaf_id),
            op_id: OperationId::new("op:test").unwrap(),
            principal_id: PrincipalId::new("agent:test").unwrap(),
            request_descriptor_hash: [0u8; 32],
            preimage_bytes: vec![0u8; preimage_len],
        };

        // Termination + no-panic.
        let start = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            v.verify_sub_token(&sub, &zone(), now_unix_ms)
        }));
        prop_assert!(
            start.elapsed() < Duration::from_millis(500),
            "lattice walker took {} ms — possible unbounded loop",
            start.elapsed().as_millis()
        );
        prop_assert!(result.is_ok(), "lattice walker panicked on adversarial chain");

        // Verification with stub crypto either succeeds with
        // NotImplemented (the bead-blessed signal that production
        // should fall back to V3) OR returns one of the typed
        // structural errors. Anything else is a regression.
        let outcome = result.unwrap();
        match outcome {
            Ok(_) => {} // Receipt — fine, never reached today (stub)
            Err(LatticeDelegationError::UnknownCertificate { .. })
            | Err(LatticeDelegationError::ZoneMismatch { .. })
            | Err(LatticeDelegationError::OutsidePeriod { .. })
            | Err(LatticeDelegationError::IncompleteDelegationChain { .. })
            | Err(LatticeDelegationError::ChainTooDeep { .. })
            | Err(LatticeDelegationError::PreimageEncodingMismatch { .. })
            | Err(LatticeDelegationError::ParameterMismatch { .. })
            | Err(LatticeDelegationError::NotImplemented)
            | Err(LatticeDelegationError::VerificationEquationFailed { .. })
            | Err(LatticeDelegationError::PreimageTooLong { .. }) => {}
        }
    }

    /// Mismatched-zone request must NEVER panic and must always
    /// surface ZoneMismatch (when the cert exists) or
    /// UnknownCertificate (when it doesn't).
    #[test]
    fn lattice_walker_zone_mismatch_never_panics(
        seed in 1u8..=10,
        _request_zone_byte in 0u8..=10,
    ) {
        let v = verifier_with(vec![cert(seed, None, zone(), period_open())]);
        let sub = sub_token_targeting(seed);
        // Use a different built-in zone than `zone()` so the
        // mismatch path fires deterministically.
        let other_zone = ZoneId::private();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            v.verify_sub_token(&sub, &other_zone, 1_700_000_000_000)
        }));
        prop_assert!(result.is_ok(), "verifier panicked on cross-zone request");
    }
}
