//! Adversarial fuzz harness — fcp-policy capability matching
//! (testing-fuzzing alpha-domain coverage; complements CrimsonWolf's
//! 6f46e6a13 PQ-crypto sweep).
//!
//! AmberLark, 2026-05-02.
//!
//! Drives the real `DefaultConstraintEnforcer` against random
//! `CapabilityConstraints` × `RequestDescriptor` pairs and asserts:
//!
//! - **Never panics.** No proptest input may panic the enforcer.
//! - **Deterministic.** Same input → same output across two
//!   independent enforcer instances.
//! - **Bounded outcome shape.** Allow / Deny only — no third state.
//!
//! The harness builds REAL types throughout. No mocks.

use proptest::collection::vec;
use proptest::prelude::*;

use fcp_core::{CapabilityConstraints, CredentialId, ObjectId, OperationId, PrincipalId};
use fcp_policy::{
    CapabilityConstraintEnforcer, ConstraintEvaluation, DefaultConstraintEnforcer,
    RequestDescriptor,
};

/// Bound proptest input sizes so the harness stays in budget. Large
/// enough to exercise repeated entries + collisions; small enough to
/// keep `proptest` runs deterministic and fast.
const MAX_LIST_LEN: usize = 6;
const MAX_STRING_LEN: usize = 32;

/// Strategy for a printable-ASCII-ish string (no embedded NUL, no
/// control chars beyond tab/space). Constraint evaluation strings
/// are operator-facing; this matches the realistic input shape
/// without trapping in arbitrary UTF-8 normalization edge cases that
/// would mask real bugs in the matcher.
fn arb_token_string() -> impl Strategy<Value = String> {
    "[\\x20\\x09a-zA-Z0-9/_:.\\-+~%?#&=*]{0,32}"
        .prop_map(|s| s.chars().take(MAX_STRING_LEN).collect())
}

fn arb_principal() -> impl Strategy<Value = PrincipalId> {
    // Canonical-id rules (fcp-core/src/capability.rs:89): lowercase
    // ASCII only, '.', '_', ':', '-' allowed after the first char.
    "[a-z][a-z0-9_-]{0,15}"
        .prop_map(|s| PrincipalId::new(format!("user:{s}")).expect("valid principal"))
}

fn arb_operation() -> impl Strategy<Value = OperationId> {
    "[a-z][a-z0-9_.]{0,15}"
        .prop_map(|s| OperationId::new(format!("op.{s}")).expect("valid operation"))
}

fn arb_object_id() -> impl Strategy<Value = ObjectId> {
    any::<[u8; 32]>().prop_map(ObjectId::from_bytes)
}

fn arb_credential_id() -> impl Strategy<Value = CredentialId> {
    // CredentialId is a UUID wrapper; derive deterministic test
    // UUIDs from a 16-byte proptest seed so the fuzzer can shrink.
    any::<[u8; 16]>().prop_map(|bytes| CredentialId::from_uuid(uuid::Uuid::from_bytes(bytes)))
}

fn arb_constraints() -> impl Strategy<Value = CapabilityConstraints> {
    (
        vec(arb_token_string(), 0..MAX_LIST_LEN),  // resource_allow
        vec(arb_token_string(), 0..MAX_LIST_LEN),  // resource_deny
        proptest::option::of(any::<u32>()),        // max_calls
        proptest::option::of(any::<u64>()),        // max_bytes
        proptest::option::of(arb_token_string()),  // idempotency_key
        vec(arb_credential_id(), 0..MAX_LIST_LEN), // credential_allow
    )
        .prop_map(
            |(allow, deny, calls, bytes, key, credentials)| CapabilityConstraints {
                resource_allow: allow,
                resource_deny: deny,
                max_calls: calls,
                max_bytes: bytes,
                idempotency_key: key,
                credential_allow: credentials,
            },
        )
}

fn arb_request_descriptor() -> impl Strategy<Value = RequestDescriptor> {
    (
        arb_object_id(),
        arb_operation(),
        arb_principal(),
        arb_token_string(), // host
        arb_token_string(), // resource_uri
        any::<u64>(),       // requested_at_unix_ms
        any::<u32>(),       // observed_calls
        any::<u64>(),       // observed_bytes
    )
        .prop_map(
            |(object_id, operation, principal, host, resource_uri, ts, calls, bytes)| {
                RequestDescriptor {
                    object_id,
                    operation,
                    principal,
                    host,
                    resource_uri,
                    requested_at_unix_ms: ts,
                    observed_calls: calls,
                    observed_bytes: bytes,
                }
            },
        )
}

fn outcome_is_well_formed(outcome: &ConstraintEvaluation) -> bool {
    // ConstraintEvaluation is a closed enum with exactly two variants
    // (Allow / Deny). The pinned-baseline check here pins that — if a
    // future variant is added, this needs an explicit decision about
    // whether the harness should accept it.
    outcome.is_allow() || outcome.is_deny()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        // Fail-persistence is on by default; nothing to override here.
        ..ProptestConfig::default()
    })]

    /// br-AmberLark/fuzz: the constraint enforcer NEVER panics on any
    /// (CapabilityConstraints, RequestDescriptor) pair, no matter how
    /// pathological the input.
    #[test]
    fn capability_match_fuzz_never_panics(
        constraints in arb_constraints(),
        request in arb_request_descriptor(),
    ) {
        let enforcer = DefaultConstraintEnforcer::new();
        // The contract: this returns Allow or Deny but never panics.
        let outcome = enforcer.evaluate(&constraints, &request);
        prop_assert!(outcome_is_well_formed(&outcome), "enforcer must produce a well-formed outcome");
    }

    /// br-AmberLark/fuzz: the enforcer is DETERMINISTIC. Two
    /// independently-constructed enforcer instances given the same
    /// (constraints, request) pair must produce equivalent outcomes
    /// (Allow ↔ Allow, Deny ↔ Deny — denial-reason kinds may carry
    /// `observed_value` strings that depend on input ordering, so we
    /// only assert the discriminant matches, not exact equality).
    #[test]
    fn capability_match_fuzz_is_deterministic_across_instances(
        constraints in arb_constraints(),
        request in arb_request_descriptor(),
    ) {
        let a = DefaultConstraintEnforcer::new();
        let b = DefaultConstraintEnforcer::new();
        let outcome_a = a.evaluate(&constraints, &request);
        let outcome_b = b.evaluate(&constraints, &request);
        prop_assert_eq!(
            outcome_a.is_allow(),
            outcome_b.is_allow(),
            "two independent enforcer instances disagree on Allow/Deny for the same input"
        );
    }

    /// br-AmberLark/fuzz: re-evaluating the SAME enforcer instance
    /// twice with byte-identical inputs produces byte-identical
    /// Allow/Deny outcomes. Pins the no-hidden-state property
    /// documented at constraint_enforcer.rs:608.
    #[test]
    fn capability_match_fuzz_repeated_evaluation_is_idempotent(
        constraints in arb_constraints(),
        request in arb_request_descriptor(),
    ) {
        let enforcer = DefaultConstraintEnforcer::new();
        let first = enforcer.evaluate(&constraints, &request);
        let second = enforcer.evaluate(&constraints, &request);
        prop_assert_eq!(first.is_allow(), second.is_allow(),
            "same enforcer + same input must produce same Allow/Deny twice");
    }

    /// br-AmberLark/fuzz: an empty `CapabilityConstraints` always
    /// denies (default-deny floor) regardless of request shape. This
    /// is the load-bearing safety property that the dja9u typestate
    /// ratchet ultimately protects.
    #[test]
    fn capability_match_fuzz_empty_constraints_always_deny(
        request in arb_request_descriptor(),
    ) {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.evaluate(&CapabilityConstraints::default(), &request);
        prop_assert!(
            outcome.is_deny(),
            "empty constraints must default-deny ANY request; got Allow for {request:?}"
        );
    }
}
