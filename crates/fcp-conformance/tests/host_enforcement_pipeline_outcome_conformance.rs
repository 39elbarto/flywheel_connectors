//! `fcp_host::enforcement` pipeline-outcome + check-name registry
//! conformance.
//!
//! `host_enforcement_config_contract_conformance.rs` already pins
//! `EnforcementConfig`. This file pins:
//!
//! - `PipelineOutcome` Allow/Deny variants and predicates
//! - `EnforcementDecision` derived counters (allow_count, skip_count,
//!   is_allowed, checks_executed)
//! - `CheckRecord` field preservation
//! - `EnforcementCheck::name()` for the 11 documented check structs
//!   (the snake_case identifiers that flow into audit records and
//!   PipelineOutcome::Deny.check_name)
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`PipelineOutcome::Allow`** — `is_allow()` true, `is_deny()`
//!    false.
//! 2. **`PipelineOutcome::Deny`** carries `check_name`,
//!    `reason_code`, `explanation`; `is_deny()` true, `is_allow()`
//!    false.
//! 3. **`EnforcementDecision::is_allowed`** delegates to
//!    `outcome.is_allow()`.
//! 4. **`checks_executed` == `checks_run.len()`** (sanity).
//! 5. **`allow_count`** counts only `CheckOutcome::Allow` records.
//! 6. **`skip_count`** counts only `CheckOutcome::Skip` records.
//! 7. **Check name registry**: every documented struct returns the
//!    expected snake_case identifier:
//!    - CanonicalDecodeCheck → "canonical_decode"
//!    - ZoneMembershipCheck → "zone_membership"
//!    - CapabilityVerifyCheck → "capability_verify"
//!    - HolderProofCheck → "holder_proof"
//!    - CheckpointFreshnessCheck → "checkpoint_freshness"
//!    - TaintApprovalCheck → "taint_approval"
//!    - PolicyCeilingCheck → "policy_ceiling"
//!    - ConnectorManifestCheck → "connector_manifest"
//!    - RateLimitCheck → "rate_limit"
//!    - BudgetCheck → "budget"
//!    - RevocationCheck → "revocation" (NOT "revocation_freshness"
//!      — the host's RevocationCheck does both freshness AND
//!      membership; the name reflects the combined check)

use fcp_host::{
    BudgetCheck, CanonicalDecodeCheck, CapabilityVerifyCheck, CheckOutcome, CheckRecord,
    CheckpointFreshnessCheck, ConnectorManifestCheck, EnforcementCheck, EnforcementDecision,
    HolderProofCheck, PipelineOutcome, PolicyCeilingCheck, RateLimitCheck, RevocationCheck,
    TaintApprovalCheck, ZoneMembershipCheck,
};

// ─── PipelineOutcome ────────────────────────────────────────────────

#[test]
fn pipeline_outcome_allow_predicates() {
    let p = PipelineOutcome::Allow;
    assert!(p.is_allow());
    assert!(!p.is_deny());
}

#[test]
fn pipeline_outcome_deny_predicates() {
    let p = PipelineOutcome::Deny {
        check_name: "zone_membership".into(),
        reason_code: "ZONE_FORBIDDEN".into(),
        explanation: "principal not in target zone".into(),
    };
    assert!(p.is_deny());
    assert!(!p.is_allow());
}

#[test]
fn pipeline_outcome_deny_carries_check_name_reason_and_explanation() {
    let p = PipelineOutcome::Deny {
        check_name: "budget".into(),
        reason_code: "BUDGET_EXCEEDED".into(),
        explanation: "principal over monthly cap".into(),
    };
    match p {
        PipelineOutcome::Deny {
            check_name,
            reason_code,
            explanation,
        } => {
            assert_eq!(check_name, "budget");
            assert_eq!(reason_code, "BUDGET_EXCEEDED");
            assert_eq!(explanation, "principal over monthly cap");
        }
        PipelineOutcome::Allow => panic!("expected Deny"),
    }
}

// ─── EnforcementDecision derived counters ─────────────────────────

#[test]
fn enforcement_decision_is_allowed_delegates_to_outcome() {
    let allow = EnforcementDecision {
        outcome: PipelineOutcome::Allow,
        checks_run: vec![],
        elapsed_ms: 0.0,
    };
    assert!(allow.is_allowed());

    let deny = EnforcementDecision {
        outcome: PipelineOutcome::Deny {
            check_name: "x".into(),
            reason_code: "x".into(),
            explanation: "x".into(),
        },
        checks_run: vec![],
        elapsed_ms: 0.0,
    };
    assert!(!deny.is_allowed());
}

#[test]
fn enforcement_decision_checks_executed_matches_checks_run_len() {
    let d = EnforcementDecision {
        outcome: PipelineOutcome::Allow,
        checks_run: vec![
            CheckRecord {
                name: "a".into(),
                outcome: CheckOutcome::Allow,
                elapsed_ms: 0.0,
            },
            CheckRecord {
                name: "b".into(),
                outcome: CheckOutcome::Allow,
                elapsed_ms: 0.0,
            },
        ],
        elapsed_ms: 0.0,
    };
    assert_eq!(d.checks_executed(), 2);
    assert_eq!(d.checks_executed(), d.checks_run.len());
}

#[test]
fn enforcement_decision_allow_count_filters_only_allow_records() {
    let d = EnforcementDecision {
        outcome: PipelineOutcome::Allow,
        checks_run: vec![
            CheckRecord {
                name: "a".into(),
                outcome: CheckOutcome::Allow,
                elapsed_ms: 0.0,
            },
            CheckRecord {
                name: "b".into(),
                outcome: CheckOutcome::Skip {
                    reason: "n/a".into(),
                },
                elapsed_ms: 0.0,
            },
            CheckRecord {
                name: "c".into(),
                outcome: CheckOutcome::Allow,
                elapsed_ms: 0.0,
            },
            CheckRecord {
                name: "d".into(),
                outcome: CheckOutcome::Deny {
                    reason_code: "x".into(),
                    explanation: "x".into(),
                },
                elapsed_ms: 0.0,
            },
        ],
        elapsed_ms: 0.0,
    };
    assert_eq!(d.allow_count(), 2, "two Allow records MUST yield count 2");
    assert_eq!(d.skip_count(), 1, "one Skip record MUST yield count 1");
}

#[test]
fn enforcement_decision_counts_zero_for_empty_checks_run() {
    let d = EnforcementDecision {
        outcome: PipelineOutcome::Allow,
        checks_run: vec![],
        elapsed_ms: 0.0,
    };
    assert_eq!(d.checks_executed(), 0);
    assert_eq!(d.allow_count(), 0);
    assert_eq!(d.skip_count(), 0);
}

// ─── CheckRecord field preservation ───────────────────────────────

#[test]
fn check_record_preserves_name_outcome_and_elapsed_ms() {
    let rec = CheckRecord {
        name: "capability_verify".into(),
        outcome: CheckOutcome::Allow,
        elapsed_ms: 1.234,
    };
    assert_eq!(rec.name, "capability_verify");
    assert!(matches!(rec.outcome, CheckOutcome::Allow));
    assert!((rec.elapsed_ms - 1.234).abs() < f64::EPSILON);
}

// ─── Check-name registry: 11 documented checks ────────────────────

#[test]
fn canonical_decode_check_name_is_canonical_decode() {
    assert_eq!(CanonicalDecodeCheck.name(), "canonical_decode");
}

#[test]
fn zone_membership_check_name_is_zone_membership() {
    assert_eq!(ZoneMembershipCheck.name(), "zone_membership");
}

#[test]
fn capability_verify_check_name_is_capability_verify() {
    assert_eq!(CapabilityVerifyCheck.name(), "capability_verify");
}

#[test]
fn holder_proof_check_name_is_holder_proof() {
    assert_eq!(HolderProofCheck.name(), "holder_proof");
}

#[test]
fn checkpoint_freshness_check_name_is_checkpoint_freshness() {
    assert_eq!(CheckpointFreshnessCheck.name(), "checkpoint_freshness");
}

#[test]
fn taint_approval_check_name_is_taint_approval() {
    assert_eq!(TaintApprovalCheck.name(), "taint_approval");
}

#[test]
fn policy_ceiling_check_name_is_policy_ceiling() {
    assert_eq!(PolicyCeilingCheck.name(), "policy_ceiling");
}

#[test]
fn connector_manifest_check_name_is_connector_manifest() {
    assert_eq!(ConnectorManifestCheck.name(), "connector_manifest");
}

#[test]
fn rate_limit_check_name_is_rate_limit() {
    assert_eq!(RateLimitCheck.name(), "rate_limit");
}

#[test]
fn budget_check_name_is_budget() {
    assert_eq!(BudgetCheck.name(), "budget");
}

#[test]
fn revocation_check_name_is_revocation_not_revocation_freshness() {
    // NORMATIVE: the host's combined revocation check uses the
    // shorter name "revocation" (NOT "revocation_freshness") because
    // it covers both membership AND freshness in one struct. Drift
    // here would split the audit-trail name from the executing check.
    assert_eq!(
        RevocationCheck.name(),
        "revocation",
        "host RevocationCheck name MUST be 'revocation' (combined membership+freshness)"
    );
}

#[test]
fn check_name_registry_has_no_duplicates() {
    use std::collections::HashSet;
    let names: Vec<&'static str> = vec![
        CanonicalDecodeCheck.name(),
        ZoneMembershipCheck.name(),
        CapabilityVerifyCheck.name(),
        HolderProofCheck.name(),
        CheckpointFreshnessCheck.name(),
        TaintApprovalCheck.name(),
        PolicyCeilingCheck.name(),
        ConnectorManifestCheck.name(),
        RateLimitCheck.name(),
        BudgetCheck.name(),
        RevocationCheck.name(),
    ];
    let unique: HashSet<&'static str> = names.iter().copied().collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "all 11 check names MUST be distinct (no duplicates)"
    );
    assert_eq!(unique.len(), 11);
}

#[test]
fn check_names_use_snake_case_only() {
    let names = [
        CanonicalDecodeCheck.name(),
        ZoneMembershipCheck.name(),
        CapabilityVerifyCheck.name(),
        HolderProofCheck.name(),
        CheckpointFreshnessCheck.name(),
        TaintApprovalCheck.name(),
        PolicyCeilingCheck.name(),
        ConnectorManifestCheck.name(),
        RateLimitCheck.name(),
        BudgetCheck.name(),
        RevocationCheck.name(),
    ];
    for name in names {
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "check name '{name}' MUST be snake_case ASCII (lowercase + digits + underscore only)"
        );
        assert!(!name.is_empty(), "check name MUST NOT be empty");
        assert!(
            !name.starts_with('_') && !name.ends_with('_'),
            "check name '{name}' MUST NOT have leading/trailing underscore"
        );
    }
}
