//! Negative-test matrix for the five mandatory constraint kinds
//! enforced by [`DefaultConstraintEnforcer`] (m8j0q.A.4).
//!
//! For each mandatory kind the test pair verifies:
//!   * **Deny on mismatch** — the enforcer returns
//!     [`ConstraintEvaluation::Deny`] with the documented
//!     [`ConstraintDenialKind`] discriminant.
//!   * **Allow on match** — the same constraint set with a satisfying
//!     request returns [`ConstraintEvaluation::Allow`].
//!   * **Structured shape** — the denial reason carries the observed
//!     value (and, where applicable, the expected value) so the audit
//!     event downstream (m8j0q.A.5) has the bytes it needs.
//!   * **No side effects on deny** — invoking twice with identical
//!     inputs produces byte-identical outcomes (the enforcer is pure
//!     and stateless; this also verifies short-circuit evaluation
//!     does not mutate hidden state).
//!
//! The five mandatory kinds, per the bead acceptance:
//!   1. `ObjectIdNotInAllowlist`
//!   2. `HostNotInAllowlist`
//!   3. `OutsideTimeWindow`
//!   4. `ScopeCeilingExceeded`
//!   5. `PrincipalNotBound`
//!
//! `EmptyConstraintSet`, `ResourceUriNotInAllowlist`, and
//! `ResourceUriDeniedByDenylist` are exercised by the inline tests in
//! `crates/fcp-policy/src/constraint_enforcer.rs` and verified again
//! here only via the exhaustive-match sentinel.
//!
//! Bead: flywheel_connectors-m8j0q.4. Predecessor: m8j0q.1
//! (`CapabilityConstraintEnforcer` trait + `DefaultConstraintEnforcer`,
//! commit 7a621f827).

use fcp_core::{CapabilityConstraints, ObjectId, OperationId, PrincipalId};
use fcp_policy::{
    CapabilityConstraintEnforcer, ConstraintDenialKind, ConstraintDenialReason,
    ConstraintEvaluation, DefaultConstraintEnforcer, RequestDescriptor,
};

// ── Fixtures ────────────────────────────────────────────────────────────

fn alice() -> PrincipalId {
    PrincipalId::new("alice").expect("valid principal id")
}

fn bob() -> PrincipalId {
    PrincipalId::new("bob").expect("valid principal id")
}

fn op(name: &str) -> OperationId {
    OperationId::new(name).expect("valid operation id")
}

fn obj(name: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(name.as_bytes())
}

fn descriptor() -> RequestDescriptor {
    RequestDescriptor {
        object_id: obj("repo:flywheel-private"),
        operation: op("github.issues.create"),
        principal: alice(),
        host: "api.github.com".to_string(),
        resource_uri: "/v1/issues".to_string(),
        requested_at_unix_ms: 1_700_000_000_000,
        observed_calls: 0,
        observed_bytes: 0,
    }
}

fn assert_no_side_effects<F>(f: F)
where
    F: Fn() -> ConstraintEvaluation,
{
    let first = f();
    let second = f();
    let third = f();
    assert_eq!(
        first, second,
        "second invocation diverged from first — enforcer is not pure"
    );
    assert_eq!(
        second, third,
        "third invocation diverged from second — enforcer accumulates state"
    );
}

// ── 1. object_id allowlist ──────────────────────────────────────────────

#[test]
fn mandatory_kind_object_id_allowlist_denies_on_mismatch() {
    let enforcer = DefaultConstraintEnforcer::new();
    let allowed = vec![obj("repo:public-docs"), obj("repo:flywheel-public")];
    let observed = obj("repo:flywheel-private");
    let outcome = enforcer.enforce_object_id_allowlist(&allowed, &observed);
    assert!(outcome.is_deny(), "expected deny for {observed} not in allowlist");
    match &outcome.deny_reason().expect("deny reason present").kind {
        ConstraintDenialKind::ObjectIdNotInAllowlist { observed: o } => {
            assert_eq!(*o, observed, "denial reason must carry the rejected object_id");
        }
        other => panic!("expected ObjectIdNotInAllowlist, got {other:?}"),
    }
    assert_no_side_effects(|| enforcer.enforce_object_id_allowlist(&allowed, &observed));
}

#[test]
fn mandatory_kind_object_id_allowlist_allows_on_match() {
    let enforcer = DefaultConstraintEnforcer::new();
    let target = obj("repo:flywheel-public");
    let allowed = vec![obj("repo:public-docs"), target];
    let outcome = enforcer.enforce_object_id_allowlist(&allowed, &target);
    assert!(outcome.is_allow(), "expected allow when object_id is in allowlist");
}

// ── 2. host allowlist ───────────────────────────────────────────────────

#[test]
fn mandatory_kind_host_allowlist_denies_on_mismatch() {
    let enforcer = DefaultConstraintEnforcer::new();
    let allowed = vec!["api.github.com".to_string()];
    let observed = "api.gitlab.com";
    let outcome = enforcer.enforce_host_allowlist(&allowed, observed);
    assert!(outcome.is_deny(), "expected deny for host {observed}");
    match &outcome.deny_reason().expect("deny reason present").kind {
        ConstraintDenialKind::HostNotInAllowlist { observed: o } => {
            assert_eq!(o, observed, "denial reason must carry the rejected host");
        }
        other => panic!("expected HostNotInAllowlist, got {other:?}"),
    }
    assert_no_side_effects(|| enforcer.enforce_host_allowlist(&allowed, observed));
}

#[test]
fn mandatory_kind_host_allowlist_allows_on_match() {
    let enforcer = DefaultConstraintEnforcer::new();
    let allowed = vec!["api.github.com".to_string()];
    let outcome = enforcer.enforce_host_allowlist(&allowed, "api.github.com");
    assert!(outcome.is_allow());
}

// ── 3. time window ──────────────────────────────────────────────────────

#[test]
fn mandatory_kind_time_window_denies_when_request_is_before_not_before() {
    let enforcer = DefaultConstraintEnforcer::new();
    let nbf = 1_700_000_000_000_u64;
    let naf = 1_800_000_000_000_u64;
    let observed = 1_699_999_999_999_u64; // one ms before window opens
    let outcome = enforcer.enforce_time_window(Some(nbf), Some(naf), observed);
    assert!(outcome.is_deny(), "expected deny when before not_before");
    match &outcome.deny_reason().expect("deny reason present").kind {
        ConstraintDenialKind::OutsideTimeWindow {
            observed_unix_ms,
            not_before_unix_ms,
            not_after_unix_ms,
        } => {
            assert_eq!(*observed_unix_ms, observed);
            assert_eq!(*not_before_unix_ms, Some(nbf));
            assert_eq!(*not_after_unix_ms, Some(naf));
        }
        other => panic!("expected OutsideTimeWindow, got {other:?}"),
    }
    assert_no_side_effects(|| enforcer.enforce_time_window(Some(nbf), Some(naf), observed));
}

#[test]
fn mandatory_kind_time_window_denies_when_request_is_after_not_after() {
    let enforcer = DefaultConstraintEnforcer::new();
    let nbf = 1_700_000_000_000_u64;
    let naf = 1_800_000_000_000_u64;
    let observed = 1_800_000_000_001_u64; // one ms after window closes
    let outcome = enforcer.enforce_time_window(Some(nbf), Some(naf), observed);
    assert!(outcome.is_deny(), "expected deny when after not_after");
    assert!(matches!(
        outcome.deny_reason().expect("deny reason present").kind,
        ConstraintDenialKind::OutsideTimeWindow { .. }
    ));
}

#[test]
fn mandatory_kind_time_window_allows_within_bounds() {
    let enforcer = DefaultConstraintEnforcer::new();
    let outcome = enforcer.enforce_time_window(
        Some(1_700_000_000_000),
        Some(1_800_000_000_000),
        1_750_000_000_000,
    );
    assert!(outcome.is_allow());
}

// ── 4. scope ceiling ────────────────────────────────────────────────────

#[test]
fn mandatory_kind_scope_ceiling_denies_when_max_calls_exceeded() {
    let enforcer = DefaultConstraintEnforcer::new();
    let outcome = enforcer.enforce_scope_ceiling(Some(10), Some(1_000_000), 11, 0);
    assert!(outcome.is_deny(), "expected deny when observed_calls > max_calls");
    match &outcome.deny_reason().expect("deny reason present").kind {
        ConstraintDenialKind::ScopeCeilingExceeded {
            observed_calls,
            observed_bytes,
            max_calls,
            max_bytes,
        } => {
            assert_eq!(*observed_calls, 11);
            assert_eq!(*observed_bytes, 0);
            assert_eq!(*max_calls, Some(10));
            assert_eq!(*max_bytes, Some(1_000_000));
        }
        other => panic!("expected ScopeCeilingExceeded, got {other:?}"),
    }
    assert_no_side_effects(|| enforcer.enforce_scope_ceiling(Some(10), Some(1_000_000), 11, 0));
}

#[test]
fn mandatory_kind_scope_ceiling_denies_when_max_bytes_exceeded() {
    let enforcer = DefaultConstraintEnforcer::new();
    let outcome = enforcer.enforce_scope_ceiling(Some(100), Some(2048), 0, 2049);
    assert!(outcome.is_deny(), "expected deny when observed_bytes > max_bytes");
    assert!(matches!(
        outcome.deny_reason().expect("deny reason present").kind,
        ConstraintDenialKind::ScopeCeilingExceeded { .. }
    ));
}

#[test]
fn mandatory_kind_scope_ceiling_allows_at_inclusive_boundary() {
    let enforcer = DefaultConstraintEnforcer::new();
    // Exactly equal to the ceiling is allowed (deny is `>`, not `>=`).
    let outcome = enforcer.enforce_scope_ceiling(Some(10), Some(1024), 10, 1024);
    assert!(outcome.is_allow(), "max_calls / max_bytes are inclusive bounds");
}

// ── 5. principal binding ────────────────────────────────────────────────

#[test]
fn mandatory_kind_principal_binding_denies_when_request_principal_differs() {
    let enforcer = DefaultConstraintEnforcer::new();
    let bound = alice();
    let observed = bob();
    let outcome = enforcer.enforce_principal_binding(Some(&bound), &observed);
    assert!(outcome.is_deny(), "expected deny when principals differ");
    match &outcome.deny_reason().expect("deny reason present").kind {
        ConstraintDenialKind::PrincipalNotBound {
            observed: o,
            expected: e,
        } => {
            assert_eq!(o, &observed, "denial must carry the rejected principal");
            assert_eq!(e, &bound, "denial must carry the bound principal");
        }
        other => panic!("expected PrincipalNotBound, got {other:?}"),
    }
    assert_no_side_effects(|| {
        enforcer.enforce_principal_binding(Some(&bound), &observed)
    });
}

#[test]
fn mandatory_kind_principal_binding_allows_when_request_principal_matches() {
    let enforcer = DefaultConstraintEnforcer::new();
    let bound = alice();
    let outcome = enforcer.enforce_principal_binding(Some(&bound), &bound);
    assert!(outcome.is_allow());
}

#[test]
fn mandatory_kind_principal_binding_unbound_allows_any_principal() {
    let enforcer = DefaultConstraintEnforcer::new();
    let outcome = enforcer.enforce_principal_binding(None, &alice());
    assert!(outcome.is_allow());
    let outcome2 = enforcer.enforce_principal_binding(None, &bob());
    assert!(outcome2.is_allow());
}

// ── Cross-cutting structural invariants ────────────────────────────────

#[test]
fn denial_kind_exhaustive_match_sentinel() {
    // Constructing one of each variant and exhaustively matching keeps
    // the m8j0q.A.4 acceptance in sync with the live enum: when a new
    // ConstraintDenialKind lands, this test fails to compile and the
    // author must extend the negative-test matrix above (or document
    // why the new kind is exempt from A.4 coverage).
    let probes = [
        ConstraintDenialKind::EmptyConstraintSet,
        ConstraintDenialKind::ObjectIdNotInAllowlist {
            observed: obj("x"),
        },
        ConstraintDenialKind::HostNotInAllowlist {
            observed: "x".to_string(),
        },
        ConstraintDenialKind::ResourceUriNotInAllowlist {
            observed: "/x".to_string(),
        },
        ConstraintDenialKind::ResourceUriDeniedByDenylist {
            observed: "/x".to_string(),
            matched_pattern: "/x*".to_string(),
        },
        ConstraintDenialKind::OutsideTimeWindow {
            observed_unix_ms: 0,
            not_before_unix_ms: None,
            not_after_unix_ms: None,
        },
        ConstraintDenialKind::ScopeCeilingExceeded {
            observed_calls: 0,
            observed_bytes: 0,
            max_calls: None,
            max_bytes: None,
        },
        ConstraintDenialKind::PrincipalNotBound {
            observed: alice(),
            expected: bob(),
        },
    ];
    assert_eq!(
        probes.len(),
        8,
        "ConstraintDenialKind variant count drift: expected 8, got {}",
        probes.len()
    );
    for kind in &probes {
        match kind {
            ConstraintDenialKind::EmptyConstraintSet
            | ConstraintDenialKind::ObjectIdNotInAllowlist { .. }
            | ConstraintDenialKind::HostNotInAllowlist { .. }
            | ConstraintDenialKind::ResourceUriNotInAllowlist { .. }
            | ConstraintDenialKind::ResourceUriDeniedByDenylist { .. }
            | ConstraintDenialKind::OutsideTimeWindow { .. }
            | ConstraintDenialKind::ScopeCeilingExceeded { .. }
            | ConstraintDenialKind::PrincipalNotBound { .. } => (),
        }
    }
}

#[test]
fn denial_reason_round_trips_through_json_for_every_mandatory_kind() {
    // Audit consumers (m8j0q.A.5) serialize ConstraintDenialReason to
    // JSON for the audit log. Verify each mandatory kind survives the
    // round-trip byte-equivalent so the {kind, observed, expected,
    // matched_pattern} fields the audit log carries are stable.
    let cases = [
        ConstraintDenialReason {
            kind: ConstraintDenialKind::ObjectIdNotInAllowlist {
                observed: obj("repo:flywheel-private"),
            },
            explanation: "object_id not in allowlist of 2 entries".to_string(),
        },
        ConstraintDenialReason {
            kind: ConstraintDenialKind::HostNotInAllowlist {
                observed: "api.gitlab.com".to_string(),
            },
            explanation: "host api.gitlab.com not in allowlist of 1 entries".to_string(),
        },
        ConstraintDenialReason {
            kind: ConstraintDenialKind::OutsideTimeWindow {
                observed_unix_ms: 1_699_999_999_999,
                not_before_unix_ms: Some(1_700_000_000_000),
                not_after_unix_ms: Some(1_800_000_000_000),
            },
            explanation: "request_time before not_before".to_string(),
        },
        ConstraintDenialReason {
            kind: ConstraintDenialKind::ScopeCeilingExceeded {
                observed_calls: 11,
                observed_bytes: 0,
                max_calls: Some(10),
                max_bytes: Some(1024),
            },
            explanation: "observed_calls 11 exceeds max_calls 10".to_string(),
        },
        ConstraintDenialReason {
            kind: ConstraintDenialKind::PrincipalNotBound {
                observed: bob(),
                expected: alice(),
            },
            explanation: "principal bob does not match bound alice".to_string(),
        },
    ];
    for original in cases {
        let json = serde_json::to_string(&original).expect("serialize denial reason");
        let back: ConstraintDenialReason =
            serde_json::from_str(&json).expect("deserialize denial reason");
        assert_eq!(
            back, original,
            "JSON round-trip diverged for {:?}; wire form: {json}",
            original.kind
        );
    }
}

// ── Top-level evaluate() integration ───────────────────────────────────

#[test]
fn evaluate_orchestration_short_circuits_on_first_deny() {
    // Default-deny check fires before any subsequent check, so even a
    // request that would otherwise satisfy everything is rejected with
    // EmptyConstraintSet — proving short-circuit semantics.
    let enforcer = DefaultConstraintEnforcer::new();
    let outcome = enforcer.evaluate(&CapabilityConstraints::default(), &descriptor());
    assert!(outcome.is_deny());
    assert_eq!(
        outcome.deny_reason().expect("deny reason").kind,
        ConstraintDenialKind::EmptyConstraintSet
    );
}

#[test]
fn evaluate_orchestration_routes_scope_ceiling_through_top_level_path() {
    let enforcer = DefaultConstraintEnforcer::new();
    let constraints = CapabilityConstraints {
        max_calls: Some(5),
        ..CapabilityConstraints::default()
    };
    let mut req = descriptor();
    req.observed_calls = 6;
    let outcome = enforcer.evaluate(&constraints, &req);
    assert!(matches!(
        outcome.deny_reason().expect("deny reason").kind,
        ConstraintDenialKind::ScopeCeilingExceeded { .. }
    ));
}
