//! Canonical enforcement check ordering for the FCP security pipeline.
//!
//! This module defines the mesh-native enforcement check ordering that SDKs,
//! hosts, and other runtimes must follow when validating requests. Previously
//! this ordering was only defined in `fcp-host`; this module makes it a
//! first-class contract that any runtime can depend on.
//!
//! # Check Ordering (NORMATIVE)
//!
//! The enforcement pipeline runs 12 checks in sequence, short-circuiting
//! at the first denial:
//!
//! 1. **Canonical decode** — validates request has required non-empty fields
//! 2. **Zone membership** — validates principal is allowed in the zone
//! 3. **Capability verify** — validates capability claims include the required capability
//! 4. **Holder proof** — validates holder-bound tokens present a verified holder proof
//! 5. **Checkpoint freshness** — validates checkpoint age is within window
//! 6. **Revocation freshness** — validates revocation list age is within window
//! 7. **Taint approval** — validates critical taints have approval tokens
//! 8. **Policy ceiling** — validates zone policy permits connector/operation
//! 9. **Capability constraints** — validates token constraints against request details
//! 10. **Connector manifest** — validates manifest includes the operation
//! 11. **Budget** — validates request is within the current usage budget
//! 12. **Rate limit** — validates request is within rate quota

use serde::{Deserialize, Serialize};

/// Canonical enforcement check identifier.
///
/// Each variant represents one stage in the enforcement pipeline. The ordering
/// defined by [`EnforcementCheckOrder::canonical_order`] is NORMATIVE — all
/// runtimes MUST evaluate checks in this sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementCheckId {
    /// Validates request has required non-empty fields.
    CanonicalDecode,
    /// Validates principal is allowed in the zone.
    ZoneMembership,
    /// Validates capability claims include the required capability.
    CapabilityVerify,
    /// Validates holder-bound tokens present a verified holder proof.
    HolderProof,
    /// Validates checkpoint age is within window.
    CheckpointFreshness,
    /// Validates revocation list age is within window.
    RevocationFreshness,
    /// Validates critical taints have approval tokens.
    TaintApproval,
    /// Validates zone policy permits connector/operation.
    PolicyCeiling,
    /// Validates capability-token constraints against request details.
    CapabilityConstraints,
    /// Validates manifest includes the operation.
    ConnectorManifest,
    /// Validates request is within the current usage budget.
    Budget,
    /// Validates request is within rate quota.
    RateLimit,
}

impl EnforcementCheckId {
    /// Stable string name for this check (used in audit logs and API responses).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CanonicalDecode => "canonical_decode",
            Self::ZoneMembership => "zone_membership",
            Self::CapabilityVerify => "capability_verify",
            Self::HolderProof => "holder_proof",
            Self::CheckpointFreshness => "checkpoint_freshness",
            Self::RevocationFreshness => "revocation_freshness",
            Self::TaintApproval => "taint_approval",
            Self::PolicyCeiling => "policy_ceiling",
            Self::CapabilityConstraints => "capability_constraints",
            Self::ConnectorManifest => "connector_manifest",
            Self::Budget => "budget",
            Self::RateLimit => "rate_limit",
        }
    }
}

impl std::fmt::Display for EnforcementCheckId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The canonical enforcement check ordering (NORMATIVE).
///
/// All FCP runtimes MUST evaluate enforcement checks in this order. The
/// ordering is designed so that cheaper structural checks (decode, zone
/// membership) run before expensive cryptographic checks (capability verify,
/// holder proof), which run before stateful checks (budget, rate limit).
pub struct EnforcementCheckOrder;

impl EnforcementCheckOrder {
    /// Total number of checks in the canonical pipeline.
    pub const COUNT: usize = 12;

    /// Returns the canonical check ordering.
    ///
    /// This is the single source of truth for enforcement pipeline sequencing.
    /// The host, SDK, and any future runtime MUST use this ordering.
    #[must_use]
    pub const fn canonical_order() -> [EnforcementCheckId; Self::COUNT] {
        [
            EnforcementCheckId::CanonicalDecode,
            EnforcementCheckId::ZoneMembership,
            EnforcementCheckId::CapabilityVerify,
            EnforcementCheckId::HolderProof,
            EnforcementCheckId::CheckpointFreshness,
            EnforcementCheckId::RevocationFreshness,
            EnforcementCheckId::TaintApproval,
            EnforcementCheckId::PolicyCeiling,
            EnforcementCheckId::CapabilityConstraints,
            EnforcementCheckId::ConnectorManifest,
            EnforcementCheckId::Budget,
            EnforcementCheckId::RateLimit,
        ]
    }

    /// Returns the 0-based index of a check in the canonical order.
    #[must_use]
    pub const fn index_of(check: EnforcementCheckId) -> usize {
        match check {
            EnforcementCheckId::CanonicalDecode => 0,
            EnforcementCheckId::ZoneMembership => 1,
            EnforcementCheckId::CapabilityVerify => 2,
            EnforcementCheckId::HolderProof => 3,
            EnforcementCheckId::CheckpointFreshness => 4,
            EnforcementCheckId::RevocationFreshness => 5,
            EnforcementCheckId::TaintApproval => 6,
            EnforcementCheckId::PolicyCeiling => 7,
            EnforcementCheckId::CapabilityConstraints => 8,
            EnforcementCheckId::ConnectorManifest => 9,
            EnforcementCheckId::Budget => 10,
            EnforcementCheckId::RateLimit => 11,
        }
    }

    /// Returns true if `a` must run before `b` in the canonical order.
    #[must_use]
    pub const fn runs_before(a: EnforcementCheckId, b: EnforcementCheckId) -> bool {
        Self::index_of(a) < Self::index_of(b)
    }
}

/// Outcome of a single enforcement check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    /// Check passed — request may proceed to the next check.
    Allow,
    /// Check denied — request MUST be rejected.
    Deny {
        /// Machine-readable reason code (e.g., `zone_violation`).
        reason_code: String,
        /// Human-readable explanation for operators.
        explanation: String,
    },
    /// Check was skipped (e.g., not applicable for this request type).
    Skip {
        /// Why the check was skipped.
        reason: String,
    },
}

impl CheckOutcome {
    /// Whether this outcome allows the request to proceed.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this outcome denies the request.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Whether this outcome skipped the check without allowing or denying.
    #[must_use]
    pub const fn is_skip(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }
}

/// Audit record for a single check execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRecord {
    /// Which check ran.
    pub check: EnforcementCheckId,
    /// What it decided.
    pub outcome: CheckOutcome,
    /// How long it took in microseconds.
    pub elapsed_us: u64,
}

/// Result of the full enforcement pipeline evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementDecision {
    /// Overall outcome (Allow if all checks passed, Deny at first denial).
    pub outcome: CheckOutcome,
    /// Ordered record of every check that ran.
    pub checks_run: Vec<CheckRecord>,
    /// Total pipeline evaluation time in microseconds.
    pub total_elapsed_us: u64,
}

impl EnforcementDecision {
    /// Whether the pipeline allowed the request.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.outcome.is_allow()
    }

    /// How many checks ran before the decision was reached.
    #[must_use]
    pub fn checks_evaluated(&self) -> usize {
        self.checks_run.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_order_has_12_checks() {
        assert_eq!(EnforcementCheckOrder::canonical_order().len(), 12);
        assert_eq!(EnforcementCheckOrder::COUNT, 12);
    }

    #[test]
    fn canonical_order_starts_with_decode_ends_with_rate_limit() {
        let order = EnforcementCheckOrder::canonical_order();
        assert_eq!(order[0], EnforcementCheckId::CanonicalDecode);
        assert_eq!(order[11], EnforcementCheckId::RateLimit);
    }

    #[test]
    fn canonical_order_all_unique() {
        let order = EnforcementCheckOrder::canonical_order();
        let mut seen = std::collections::HashSet::new();
        for check in &order {
            assert!(seen.insert(check), "duplicate check: {check:?}");
        }
    }

    #[test]
    fn index_of_matches_canonical_order() {
        let order = EnforcementCheckOrder::canonical_order();
        for (i, check) in order.iter().enumerate() {
            assert_eq!(
                EnforcementCheckOrder::index_of(*check),
                i,
                "index mismatch for {check:?}"
            );
        }
    }

    #[test]
    fn runs_before_structural_before_crypto() {
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::CanonicalDecode,
            EnforcementCheckId::CapabilityVerify,
        ));
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::ZoneMembership,
            EnforcementCheckId::HolderProof,
        ));
    }

    #[test]
    fn runs_before_crypto_before_stateful() {
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::CapabilityVerify,
            EnforcementCheckId::Budget,
        ));
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::HolderProof,
            EnforcementCheckId::RateLimit,
        ));
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::PolicyCeiling,
            EnforcementCheckId::CapabilityConstraints,
        ));
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::CapabilityConstraints,
            EnforcementCheckId::RateLimit,
        ));
    }

    #[test]
    fn runs_before_is_asymmetric() {
        assert!(EnforcementCheckOrder::runs_before(
            EnforcementCheckId::CanonicalDecode,
            EnforcementCheckId::RateLimit,
        ));
        assert!(!EnforcementCheckOrder::runs_before(
            EnforcementCheckId::RateLimit,
            EnforcementCheckId::CanonicalDecode,
        ));
    }

    #[test]
    fn runs_before_same_check_is_false() {
        assert!(!EnforcementCheckOrder::runs_before(
            EnforcementCheckId::Budget,
            EnforcementCheckId::Budget,
        ));
    }

    #[test]
    fn check_id_as_str_roundtrip() {
        let order = EnforcementCheckOrder::canonical_order();
        for check in &order {
            let s = check.as_str();
            assert!(!s.is_empty(), "empty name for {check:?}");
            let json = serde_json::to_string(check).unwrap();
            assert!(json.contains(s), "serde name mismatch for {check:?}");
        }
    }

    #[test]
    fn check_id_display() {
        assert_eq!(
            EnforcementCheckId::CanonicalDecode.to_string(),
            "canonical_decode"
        );
        assert_eq!(EnforcementCheckId::RateLimit.to_string(), "rate_limit");
    }

    #[test]
    fn check_outcome_allow() {
        let outcome = CheckOutcome::Allow;
        assert!(outcome.is_allow());
        assert!(!outcome.is_deny());
    }

    #[test]
    fn check_outcome_deny() {
        let outcome = CheckOutcome::Deny {
            reason_code: "zone_violation".into(),
            explanation: "principal not in zone".into(),
        };
        assert!(!outcome.is_allow());
        assert!(outcome.is_deny());
    }

    #[test]
    fn check_outcome_skip() {
        let outcome = CheckOutcome::Skip {
            reason: "not applicable".into(),
        };
        assert!(!outcome.is_allow());
        assert!(!outcome.is_deny());
    }

    #[test]
    fn check_outcome_serde_roundtrip() {
        let outcomes = vec![
            CheckOutcome::Allow,
            CheckOutcome::Deny {
                reason_code: "test".into(),
                explanation: "test".into(),
            },
            CheckOutcome::Skip {
                reason: "test".into(),
            },
        ];
        for outcome in &outcomes {
            let json = serde_json::to_string(outcome).unwrap();
            let decoded: CheckOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, &decoded);
        }
    }

    #[test]
    fn enforcement_decision_allowed() {
        let decision = EnforcementDecision {
            outcome: CheckOutcome::Allow,
            checks_run: vec![
                CheckRecord {
                    check: EnforcementCheckId::CanonicalDecode,
                    outcome: CheckOutcome::Allow,
                    elapsed_us: 10,
                },
                CheckRecord {
                    check: EnforcementCheckId::ZoneMembership,
                    outcome: CheckOutcome::Allow,
                    elapsed_us: 20,
                },
            ],
            total_elapsed_us: 30,
        };
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_evaluated(), 2);
    }

    #[test]
    fn enforcement_decision_denied_short_circuits() {
        let decision = EnforcementDecision {
            outcome: CheckOutcome::Deny {
                reason_code: "zone_violation".into(),
                explanation: "not in zone".into(),
            },
            checks_run: vec![
                CheckRecord {
                    check: EnforcementCheckId::CanonicalDecode,
                    outcome: CheckOutcome::Allow,
                    elapsed_us: 5,
                },
                CheckRecord {
                    check: EnforcementCheckId::ZoneMembership,
                    outcome: CheckOutcome::Deny {
                        reason_code: "zone_violation".into(),
                        explanation: "not in zone".into(),
                    },
                    elapsed_us: 15,
                },
            ],
            total_elapsed_us: 20,
        };
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_evaluated(), 2);
    }

    #[test]
    fn check_record_serde_roundtrip() {
        let record = CheckRecord {
            check: EnforcementCheckId::Budget,
            outcome: CheckOutcome::Allow,
            elapsed_us: 42,
        };
        let json = serde_json::to_string(&record).unwrap();
        let decoded: CheckRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.check, EnforcementCheckId::Budget);
        assert_eq!(decoded.elapsed_us, 42);
    }

    #[test]
    fn enforcement_check_id_clone_eq() {
        let a = EnforcementCheckId::TaintApproval;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enforcement_check_id_hash() {
        let mut set = std::collections::HashSet::new();
        set.insert(EnforcementCheckId::Budget);
        set.insert(EnforcementCheckId::Budget);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn all_check_ids_serde_roundtrip() {
        for check in &EnforcementCheckOrder::canonical_order() {
            let json = serde_json::to_string(check).unwrap();
            let decoded: EnforcementCheckId = serde_json::from_str(&json).unwrap();
            assert_eq!(check, &decoded, "serde roundtrip failed for {check:?}");
        }
    }
}
