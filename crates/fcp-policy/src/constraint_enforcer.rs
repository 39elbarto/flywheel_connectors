//! Capability constraint enforcement (m8j0q.A.1).
//!
//! Defines [`CapabilityConstraintEnforcer`], the trait that mechanically
//! enforces [`CapabilityConstraints`] claims at request execution time.
//!
//! Per the FCP3 module-ownership map this lives in `fcp-policy` (the canonical
//! home post-MOVE), NOT in `fcp-core` (the semantic junk drawer being retired)
//! and NOT in `fcp-host` (host MUST NOT own policy semantics — see FCP3
//! forbidden-overlap F3).
//!
//! ## Design contract
//!
//! - **Default-deny.** An empty [`CapabilityConstraints`] denies every request
//!   (matches `CapabilityConstraints::is_empty` and the C3.4 invariant).
//! - **Short-circuit.** [`CapabilityConstraintEnforcer::evaluate`] returns the
//!   first denial reason and never re-evaluates later checks.
//! - **Monotone.** Strengthening a constraint set never converts a previous
//!   `Deny` into an `Allow` (verified by proptest in `tests/`).
//! - **Order-independent.** Per-constraint methods are pure functions of their
//!   inputs; orchestration order does not change the outcome.
//! - **Structured logging.** Every evaluation emits a `tracing` event whose
//!   fields are stable for downstream `audit::CapabilityConstraintDenied`
//!   (m8j0q.A.5) consumers.
//!
//! See bead `flywheel_connectors-m8j0q.1` for goal and acceptance criteria.

use serde::{Deserialize, Serialize};

use fcp_core::{CapabilityConstraints, ObjectId, OperationId, PrincipalId};

/// Description of a request being checked against [`CapabilityConstraints`].
///
/// The enforcer extracts the relevant fields per per-constraint method. New
/// fields may be added; consumers SHOULD use the helper constructors rather
/// than struct literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDescriptor {
    /// Content-addressed object the request targets.
    pub object_id: ObjectId,
    /// Operation being invoked.
    pub operation: OperationId,
    /// Principal performing the request.
    pub principal: PrincipalId,
    /// Egress host (lowercase, no scheme/port). Empty for non-egress requests.
    pub host: String,
    /// Resource URI for `resource_allow`/`resource_deny` matching. Empty when
    /// the request does not address a URI-shaped resource.
    pub resource_uri: String,
    /// Wall-clock time of the request (Unix milliseconds).
    pub requested_at_unix_ms: u64,
    /// Cumulative invocations observed against this capability so far.
    pub observed_calls: u32,
    /// Cumulative bytes transferred against this capability so far.
    pub observed_bytes: u64,
}

/// Outcome of evaluating constraints against a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ConstraintEvaluation {
    /// All checks passed; request may proceed.
    Allow,
    /// One check denied the request; subsequent checks were skipped.
    Deny(ConstraintDenialReason),
}

impl ConstraintEvaluation {
    /// Whether this evaluation allows the request to proceed.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this evaluation denies the request.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// Borrow the denial reason, if any.
    #[must_use]
    pub const fn deny_reason(&self) -> Option<&ConstraintDenialReason> {
        match self {
            Self::Allow => None,
            Self::Deny(reason) => Some(reason),
        }
    }
}

/// Structured denial reason produced by a failed constraint check.
///
/// Stable across releases — downstream audit consumers depend on the
/// [`ConstraintDenialKind`] discriminant being byte-equivalent for replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintDenialReason {
    /// Categorical kind of denial (machine-readable).
    pub kind: ConstraintDenialKind,
    /// Human-readable explanation for operators.
    pub explanation: String,
}

/// Categorical reasons a request can be denied by constraint enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConstraintDenialKind {
    /// Constraint set was empty — default-deny applied.
    EmptyConstraintSet,
    /// `object_id` was not in the per-capability allowlist.
    ObjectIdNotInAllowlist {
        /// The object id that was rejected.
        observed: ObjectId,
    },
    /// Egress host was not in the per-capability allowlist.
    HostNotInAllowlist {
        /// The host that was rejected.
        observed: String,
    },
    /// Resource URI was not present in `resource_allow`.
    ResourceUriNotInAllowlist {
        /// The resource URI that was rejected.
        observed: String,
    },
    /// Resource URI matched an entry in `resource_deny`.
    ResourceUriDeniedByDenylist {
        /// The resource URI that was rejected.
        observed: String,
        /// The denylist pattern that matched.
        matched_pattern: String,
    },
    /// Request fell outside the capability's `[not_before, not_after]` window.
    OutsideTimeWindow {
        /// Request time (Unix ms).
        observed_unix_ms: u64,
        /// Lower bound of the allowed window, if any.
        not_before_unix_ms: Option<u64>,
        /// Upper bound of the allowed window, if any.
        not_after_unix_ms: Option<u64>,
    },
    /// Request would exceed `max_calls` or `max_bytes`.
    ScopeCeilingExceeded {
        /// Cumulative invocations observed so far.
        observed_calls: u32,
        /// Cumulative bytes observed so far.
        observed_bytes: u64,
        /// Per-capability call ceiling, if any.
        max_calls: Option<u32>,
        /// Per-capability byte ceiling, if any.
        max_bytes: Option<u64>,
    },
    /// Request principal does not match the capability's bound principal.
    PrincipalNotBound {
        /// Principal in the request.
        observed: PrincipalId,
        /// Principal the capability is bound to.
        expected: PrincipalId,
    },
}

impl ConstraintDenialKind {
    /// Stable machine label used by logs and audit events.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyConstraintSet => "empty_constraint_set",
            Self::ObjectIdNotInAllowlist { .. } => "object_id_not_in_allowlist",
            Self::HostNotInAllowlist { .. } => "host_not_in_allowlist",
            Self::ResourceUriNotInAllowlist { .. } => "resource_uri_not_in_allowlist",
            Self::ResourceUriDeniedByDenylist { .. } => "resource_uri_denied_by_denylist",
            Self::OutsideTimeWindow { .. } => "outside_time_window",
            Self::ScopeCeilingExceeded { .. } => "scope_ceiling_exceeded",
            Self::PrincipalNotBound { .. } => "principal_not_bound",
        }
    }

    /// Narrow observed value that failed enforcement.
    ///
    /// This intentionally avoids serializing the full request descriptor or raw
    /// payload; audit events combine this value with a descriptor hash.
    #[must_use]
    pub fn observed_value(&self) -> String {
        match self {
            Self::EmptyConstraintSet => "constraint_set=empty".to_string(),
            Self::ObjectIdNotInAllowlist { observed } => format!("object_id={observed}"),
            Self::HostNotInAllowlist { observed } => format!("host={observed}"),
            Self::ResourceUriNotInAllowlist { observed } => {
                format!("resource_uri={observed}")
            }
            Self::ResourceUriDeniedByDenylist {
                observed,
                matched_pattern,
            } => format!("resource_uri={observed},matched_pattern={matched_pattern}"),
            Self::OutsideTimeWindow {
                observed_unix_ms,
                not_before_unix_ms,
                not_after_unix_ms,
            } => format!(
                "requested_at_unix_ms={observed_unix_ms},not_before_unix_ms={not_before_unix_ms:?},not_after_unix_ms={not_after_unix_ms:?}"
            ),
            Self::ScopeCeilingExceeded {
                observed_calls,
                observed_bytes,
                max_calls,
                max_bytes,
            } => format!(
                "observed_calls={observed_calls},observed_bytes={observed_bytes},max_calls={max_calls:?},max_bytes={max_bytes:?}"
            ),
            Self::PrincipalNotBound { observed, expected } => {
                format!("principal={observed},expected={expected}")
            }
        }
    }
}

/// Mechanically enforce [`CapabilityConstraints`] claims against a request.
///
/// Implementations MUST short-circuit at the first denial and MUST treat an
/// empty constraint set as a denial (default-deny per C3.4).
pub trait CapabilityConstraintEnforcer {
    /// Evaluate the full constraint set against `request`.
    fn evaluate(
        &self,
        constraints: &CapabilityConstraints,
        request: &RequestDescriptor,
    ) -> ConstraintEvaluation;

    /// Enforce a per-capability `object_id` allowlist.
    fn enforce_object_id_allowlist(
        &self,
        allowed: &[ObjectId],
        observed: &ObjectId,
    ) -> ConstraintEvaluation;

    /// Enforce a per-capability host allowlist.
    fn enforce_host_allowlist(&self, allowed: &[String], observed: &str) -> ConstraintEvaluation;

    /// Enforce a `[not_before, not_after]` time window.
    fn enforce_time_window(
        &self,
        not_before_unix_ms: Option<u64>,
        not_after_unix_ms: Option<u64>,
        observed_unix_ms: u64,
    ) -> ConstraintEvaluation;

    /// Enforce `max_calls` / `max_bytes` ceilings.
    fn enforce_scope_ceiling(
        &self,
        max_calls: Option<u32>,
        max_bytes: Option<u64>,
        observed_calls: u32,
        observed_bytes: u64,
    ) -> ConstraintEvaluation;

    /// Enforce capability binding to a single principal.
    fn enforce_principal_binding(
        &self,
        bound: Option<&PrincipalId>,
        observed: &PrincipalId,
    ) -> ConstraintEvaluation;
}

/// Reference implementation of [`CapabilityConstraintEnforcer`].
///
/// Used by `fcp-host` (m8j0q.A.2) and the conformance vectors (m8j0q.A.4).
/// Stateless and `Copy` so multiple enforcement pipelines can share an
/// instance without lock contention.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultConstraintEnforcer;

impl DefaultConstraintEnforcer {
    /// Construct a fresh enforcer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CapabilityConstraintEnforcer for DefaultConstraintEnforcer {
    fn evaluate(
        &self,
        constraints: &CapabilityConstraints,
        request: &RequestDescriptor,
    ) -> ConstraintEvaluation {
        // C3.4 default-deny: empty constraints reject everything.
        if constraints.is_empty() {
            let outcome = ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::EmptyConstraintSet,
                explanation: "capability has no constraints — default-deny per C3.4 applies"
                    .to_string(),
            });
            log_evaluation(constraints, request, &outcome);
            return outcome;
        }

        // resource_deny precedes resource_allow — any deny match short-circuits.
        for pattern in &constraints.resource_deny {
            if pattern_matches(pattern, &request.resource_uri) {
                let outcome = ConstraintEvaluation::Deny(ConstraintDenialReason {
                    kind: ConstraintDenialKind::ResourceUriDeniedByDenylist {
                        observed: request.resource_uri.clone(),
                        matched_pattern: pattern.clone(),
                    },
                    explanation: format!(
                        "resource_uri `{}` matched resource_deny pattern `{pattern}`",
                        request.resource_uri
                    ),
                });
                log_evaluation(constraints, request, &outcome);
                return outcome;
            }
        }

        // resource_allow membership (when non-empty, request must match).
        if !constraints.resource_allow.is_empty() {
            let matched = constraints
                .resource_allow
                .iter()
                .any(|p| pattern_matches(p, &request.resource_uri));
            if !matched {
                let outcome = ConstraintEvaluation::Deny(ConstraintDenialReason {
                    kind: ConstraintDenialKind::ResourceUriNotInAllowlist {
                        observed: request.resource_uri.clone(),
                    },
                    explanation: format!(
                        "resource_uri `{}` not in resource_allow ({} patterns)",
                        request.resource_uri,
                        constraints.resource_allow.len()
                    ),
                });
                log_evaluation(constraints, request, &outcome);
                return outcome;
            }
        }

        // Scope ceilings (max_calls / max_bytes).
        let scope = self.enforce_scope_ceiling(
            constraints.max_calls,
            constraints.max_bytes,
            request.observed_calls,
            request.observed_bytes,
        );
        if scope.is_deny() {
            log_evaluation(constraints, request, &scope);
            return scope;
        }

        let outcome = ConstraintEvaluation::Allow;
        log_evaluation(constraints, request, &outcome);
        outcome
    }

    fn enforce_object_id_allowlist(
        &self,
        allowed: &[ObjectId],
        observed: &ObjectId,
    ) -> ConstraintEvaluation {
        if allowed.iter().any(|id| id == observed) {
            ConstraintEvaluation::Allow
        } else {
            ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::ObjectIdNotInAllowlist {
                    observed: *observed,
                },
                explanation: format!(
                    "object_id `{observed}` not in allowlist of {} entries",
                    allowed.len()
                ),
            })
        }
    }

    fn enforce_host_allowlist(&self, allowed: &[String], observed: &str) -> ConstraintEvaluation {
        if allowed.iter().any(|h| h.eq_ignore_ascii_case(observed)) {
            ConstraintEvaluation::Allow
        } else {
            ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::HostNotInAllowlist {
                    observed: observed.to_string(),
                },
                explanation: format!(
                    "host `{observed}` not in allowlist of {} entries",
                    allowed.len()
                ),
            })
        }
    }

    fn enforce_time_window(
        &self,
        not_before_unix_ms: Option<u64>,
        not_after_unix_ms: Option<u64>,
        observed_unix_ms: u64,
    ) -> ConstraintEvaluation {
        if let Some(nbf) = not_before_unix_ms
            && observed_unix_ms < nbf
        {
            return ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::OutsideTimeWindow {
                    observed_unix_ms,
                    not_before_unix_ms,
                    not_after_unix_ms,
                },
                explanation: format!(
                    "request_time {observed_unix_ms}ms is before not_before {nbf}ms"
                ),
            });
        }
        if let Some(naf) = not_after_unix_ms
            && observed_unix_ms > naf
        {
            return ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::OutsideTimeWindow {
                    observed_unix_ms,
                    not_before_unix_ms,
                    not_after_unix_ms,
                },
                explanation: format!(
                    "request_time {observed_unix_ms}ms is after not_after {naf}ms"
                ),
            });
        }
        ConstraintEvaluation::Allow
    }

    fn enforce_scope_ceiling(
        &self,
        max_calls: Option<u32>,
        max_bytes: Option<u64>,
        observed_calls: u32,
        observed_bytes: u64,
    ) -> ConstraintEvaluation {
        if let Some(mc) = max_calls
            && observed_calls > mc
        {
            return ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::ScopeCeilingExceeded {
                    observed_calls,
                    observed_bytes,
                    max_calls,
                    max_bytes,
                },
                explanation: format!("observed_calls {observed_calls} exceeds max_calls {mc}"),
            });
        }
        if let Some(mb) = max_bytes
            && observed_bytes > mb
        {
            return ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::ScopeCeilingExceeded {
                    observed_calls,
                    observed_bytes,
                    max_calls,
                    max_bytes,
                },
                explanation: format!("observed_bytes {observed_bytes} exceeds max_bytes {mb}"),
            });
        }
        ConstraintEvaluation::Allow
    }

    fn enforce_principal_binding(
        &self,
        bound: Option<&PrincipalId>,
        observed: &PrincipalId,
    ) -> ConstraintEvaluation {
        match bound {
            None => ConstraintEvaluation::Allow,
            Some(b) if b == observed => ConstraintEvaluation::Allow,
            Some(b) => ConstraintEvaluation::Deny(ConstraintDenialReason {
                kind: ConstraintDenialKind::PrincipalNotBound {
                    observed: observed.clone(),
                    expected: b.clone(),
                },
                explanation: format!("principal `{observed}` does not match bound principal `{b}`"),
            }),
        }
    }
}

fn pattern_matches(pattern: &str, observed: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        observed.starts_with(prefix)
    } else {
        pattern == observed
    }
}

fn log_evaluation(
    constraints: &CapabilityConstraints,
    request: &RequestDescriptor,
    outcome: &ConstraintEvaluation,
) {
    let outcome_label = match outcome {
        ConstraintEvaluation::Allow => "allow",
        ConstraintEvaluation::Deny(_) => "deny",
    };
    let reason_kind = outcome.deny_reason().map(|reason| reason.kind.as_str());

    let constraint_count = constraints.resource_allow.len()
        + constraints.resource_deny.len()
        + usize::from(constraints.max_calls.is_some())
        + usize::from(constraints.max_bytes.is_some())
        + constraints.credential_allow.len();

    tracing::debug!(
        evaluator = "DefaultConstraintEnforcer",
        outcome = outcome_label,
        reason_kind = reason_kind,
        constraint_count = constraint_count,
        principal = %request.principal,
        operation = %request.operation,
        resource_uri = %request.resource_uri,
        host = %request.host,
        observed_calls = request.observed_calls,
        observed_bytes = request.observed_bytes,
        "capability_constraint_evaluation"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(id: &str) -> PrincipalId {
        PrincipalId::new(id).expect("valid principal id")
    }

    fn operation(id: &str) -> OperationId {
        OperationId::new(id).expect("valid operation id")
    }

    fn object(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    fn descriptor(resource_uri: &str) -> RequestDescriptor {
        RequestDescriptor {
            object_id: object("test-object"),
            operation: operation("test.op"),
            principal: principal("alice"),
            host: "api.example.com".to_string(),
            resource_uri: resource_uri.to_string(),
            requested_at_unix_ms: 1_700_000_000_000,
            observed_calls: 0,
            observed_bytes: 0,
        }
    }

    #[test]
    fn denial_kind_labels_and_observed_values_are_audit_stable() {
        let kind = ConstraintDenialKind::ScopeCeilingExceeded {
            observed_calls: 1,
            observed_bytes: 512,
            max_calls: Some(0),
            max_bytes: Some(256),
        };

        assert_eq!(kind.as_str(), "scope_ceiling_exceeded");
        assert_eq!(
            kind.observed_value(),
            "observed_calls=1,observed_bytes=512,max_calls=Some(0),max_bytes=Some(256)"
        );
    }

    // ── evaluate(): default-deny on empty constraint set ──────────────────

    #[test]
    fn evaluate_empty_constraints_denies_with_default_deny_kind() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.evaluate(&CapabilityConstraints::default(), &descriptor("anything"));
        assert!(outcome.is_deny());
        assert_eq!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::EmptyConstraintSet
        );
    }

    #[test]
    fn evaluate_default_deny_explanation_mentions_c3_4() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.evaluate(&CapabilityConstraints::default(), &descriptor("/x"));
        let explanation = &outcome.deny_reason().unwrap().explanation;
        assert!(explanation.contains("C3.4"), "got: {explanation}");
    }

    // ── evaluate(): resource_allow membership ─────────────────────────────

    #[test]
    fn evaluate_allows_when_resource_uri_matches_resource_allow_exact() {
        let enforcer = DefaultConstraintEnforcer::new();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/v1/messages".to_string()],
            ..CapabilityConstraints::default()
        };
        let outcome = enforcer.evaluate(&constraints, &descriptor("/v1/messages"));
        assert!(outcome.is_allow(), "got: {outcome:?}");
    }

    #[test]
    fn evaluate_allows_when_resource_uri_matches_resource_allow_prefix() {
        let enforcer = DefaultConstraintEnforcer::new();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/v1/messages/*".to_string()],
            ..CapabilityConstraints::default()
        };
        let outcome = enforcer.evaluate(&constraints, &descriptor("/v1/messages/abc"));
        assert!(outcome.is_allow(), "got: {outcome:?}");
    }

    #[test]
    fn evaluate_denies_when_resource_uri_not_in_allow_list() {
        let enforcer = DefaultConstraintEnforcer::new();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/v1/messages".to_string()],
            ..CapabilityConstraints::default()
        };
        let outcome = enforcer.evaluate(&constraints, &descriptor("/v1/admin"));
        assert!(outcome.is_deny());
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::ResourceUriNotInAllowlist { .. }
        ));
    }

    // ── evaluate(): resource_deny precedence ──────────────────────────────

    #[test]
    fn evaluate_denies_when_resource_uri_matches_resource_deny() {
        let enforcer = DefaultConstraintEnforcer::new();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/v1/*".to_string()],
            resource_deny: vec!["/v1/admin/*".to_string()],
            ..CapabilityConstraints::default()
        };
        let outcome = enforcer.evaluate(&constraints, &descriptor("/v1/admin/keys"));
        assert!(outcome.is_deny());
        match &outcome.deny_reason().unwrap().kind {
            ConstraintDenialKind::ResourceUriDeniedByDenylist {
                matched_pattern, ..
            } => {
                assert_eq!(matched_pattern, "/v1/admin/*");
            }
            other => panic!("unexpected kind: {other:?}"),
        }
    }

    #[test]
    fn evaluate_denylist_short_circuits_before_allowlist_evaluation() {
        let enforcer = DefaultConstraintEnforcer::new();
        // resource_allow does not include /v1/admin, but resource_deny is checked first.
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/v1/messages".to_string()],
            resource_deny: vec!["/v1/admin".to_string()],
            ..CapabilityConstraints::default()
        };
        let outcome = enforcer.evaluate(&constraints, &descriptor("/v1/admin"));
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::ResourceUriDeniedByDenylist { .. }
        ));
    }

    // ── evaluate(): scope ceiling roll-up ─────────────────────────────────

    #[test]
    fn evaluate_denies_when_scope_ceiling_calls_exceeded() {
        let enforcer = DefaultConstraintEnforcer::new();
        let constraints = CapabilityConstraints {
            max_calls: Some(5),
            ..CapabilityConstraints::default()
        };
        let mut req = descriptor("");
        req.observed_calls = 6;
        let outcome = enforcer.evaluate(&constraints, &req);
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::ScopeCeilingExceeded { .. }
        ));
    }

    #[test]
    fn evaluate_allows_when_scope_ceiling_not_exceeded() {
        let enforcer = DefaultConstraintEnforcer::new();
        let constraints = CapabilityConstraints {
            max_calls: Some(5),
            max_bytes: Some(1024),
            ..CapabilityConstraints::default()
        };
        let mut req = descriptor("");
        req.observed_calls = 3;
        req.observed_bytes = 512;
        let outcome = enforcer.evaluate(&constraints, &req);
        assert!(outcome.is_allow(), "got: {outcome:?}");
    }

    // ── enforce_object_id_allowlist ───────────────────────────────────────

    #[test]
    fn object_id_allow_path_returns_allow() {
        let enforcer = DefaultConstraintEnforcer::new();
        let id = object("a");
        let outcome = enforcer.enforce_object_id_allowlist(&[id, object("b")], &id);
        assert!(outcome.is_allow());
    }

    #[test]
    fn object_id_deny_path_returns_structured_reason() {
        let enforcer = DefaultConstraintEnforcer::new();
        let allowed = vec![object("a"), object("b")];
        let observed = object("c");
        let outcome = enforcer.enforce_object_id_allowlist(&allowed, &observed);
        assert!(outcome.is_deny());
        match &outcome.deny_reason().unwrap().kind {
            ConstraintDenialKind::ObjectIdNotInAllowlist { observed: o } => {
                assert_eq!(*o, observed);
            }
            other => panic!("unexpected kind: {other:?}"),
        }
    }

    #[test]
    fn object_id_empty_allowlist_denies_everything() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_object_id_allowlist(&[], &object("x"));
        assert!(outcome.is_deny());
    }

    // ── enforce_host_allowlist ────────────────────────────────────────────

    #[test]
    fn host_allow_path_returns_allow() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_host_allowlist(
            &[
                "api.example.com".to_string(),
                "edge.example.com".to_string(),
            ],
            "api.example.com",
        );
        assert!(outcome.is_allow());
    }

    #[test]
    fn host_allow_is_case_insensitive() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome =
            enforcer.enforce_host_allowlist(&["API.example.com".to_string()], "api.example.com");
        assert!(outcome.is_allow());
    }

    #[test]
    fn host_deny_path_returns_structured_reason() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome =
            enforcer.enforce_host_allowlist(&["api.example.com".to_string()], "evil.example.com");
        assert!(outcome.is_deny());
        match &outcome.deny_reason().unwrap().kind {
            ConstraintDenialKind::HostNotInAllowlist { observed } => {
                assert_eq!(observed, "evil.example.com");
            }
            other => panic!("unexpected kind: {other:?}"),
        }
    }

    #[test]
    fn host_empty_allowlist_denies_everything() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_host_allowlist(&[], "api.example.com");
        assert!(outcome.is_deny());
    }

    // ── enforce_time_window ───────────────────────────────────────────────

    #[test]
    fn time_window_no_bounds_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_time_window(None, None, 1_000);
        assert!(outcome.is_allow());
    }

    #[test]
    fn time_window_within_bounds_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_time_window(Some(1_000), Some(2_000), 1_500);
        assert!(outcome.is_allow());
    }

    #[test]
    fn time_window_at_lower_boundary_inclusive_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_time_window(Some(1_000), Some(2_000), 1_000);
        assert!(outcome.is_allow());
    }

    #[test]
    fn time_window_at_upper_boundary_inclusive_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_time_window(Some(1_000), Some(2_000), 2_000);
        assert!(outcome.is_allow());
    }

    #[test]
    fn time_window_before_not_before_denies() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_time_window(Some(1_000), None, 999);
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::OutsideTimeWindow { .. }
        ));
    }

    #[test]
    fn time_window_after_not_after_denies() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_time_window(None, Some(2_000), 2_001);
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::OutsideTimeWindow { .. }
        ));
    }

    // ── enforce_scope_ceiling ─────────────────────────────────────────────

    #[test]
    fn scope_ceiling_no_bounds_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_scope_ceiling(None, None, 1_000_000, 1_000_000);
        assert!(outcome.is_allow());
    }

    #[test]
    fn scope_ceiling_at_max_calls_inclusive_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_scope_ceiling(Some(5), None, 5, 0);
        assert!(outcome.is_allow());
    }

    #[test]
    fn scope_ceiling_above_max_calls_denies() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_scope_ceiling(Some(5), None, 6, 0);
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::ScopeCeilingExceeded { .. }
        ));
    }

    #[test]
    fn scope_ceiling_above_max_bytes_denies() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_scope_ceiling(None, Some(1024), 0, 1025);
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::ScopeCeilingExceeded { .. }
        ));
    }

    // ── enforce_principal_binding ─────────────────────────────────────────

    #[test]
    fn principal_binding_unbound_allows_any_principal() {
        let enforcer = DefaultConstraintEnforcer::new();
        let outcome = enforcer.enforce_principal_binding(None, &principal("alice"));
        assert!(outcome.is_allow());
    }

    #[test]
    fn principal_binding_match_allows() {
        let enforcer = DefaultConstraintEnforcer::new();
        let alice = principal("alice");
        let outcome = enforcer.enforce_principal_binding(Some(&alice), &alice);
        assert!(outcome.is_allow());
    }

    #[test]
    fn principal_binding_mismatch_denies() {
        let enforcer = DefaultConstraintEnforcer::new();
        let alice = principal("alice");
        let bob = principal("bob");
        let outcome = enforcer.enforce_principal_binding(Some(&alice), &bob);
        assert!(matches!(
            outcome.deny_reason().unwrap().kind,
            ConstraintDenialKind::PrincipalNotBound { .. }
        ));
    }

    // ── ConstraintEvaluation accessors ────────────────────────────────────

    #[test]
    fn evaluation_accessors_round_trip() {
        let allow = ConstraintEvaluation::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_deny());
        assert!(allow.deny_reason().is_none());

        let deny = ConstraintEvaluation::Deny(ConstraintDenialReason {
            kind: ConstraintDenialKind::EmptyConstraintSet,
            explanation: "test".to_string(),
        });
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
        assert!(deny.deny_reason().is_some());
    }

    // ── Denial reason serde stability ─────────────────────────────────────

    #[test]
    fn denial_reason_round_trips_through_json() {
        let reason = ConstraintDenialReason {
            kind: ConstraintDenialKind::HostNotInAllowlist {
                observed: "evil.example.com".to_string(),
            },
            explanation: "host evil.example.com not in allowlist of 1 entries".to_string(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let back: ConstraintDenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }

    // ── Pattern matching primitive ────────────────────────────────────────

    #[test]
    fn pattern_matches_exact_only_when_no_wildcard() {
        assert!(pattern_matches("/v1/x", "/v1/x"));
        assert!(!pattern_matches("/v1/x", "/v1/x/y"));
    }

    #[test]
    fn pattern_matches_prefix_with_trailing_wildcard() {
        assert!(pattern_matches("/v1/*", "/v1/anything"));
        assert!(pattern_matches("/v1/*", "/v1/"));
        assert!(!pattern_matches("/v1/*", "/v2/anything"));
    }
}
