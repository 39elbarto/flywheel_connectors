//! Conformance tests: host-layer default-deny for missing capability, per zone.
//!
//! Drives the full 11-check `EnforcementPipeline` for each of the four
//! canonical zones (`z:private`, `z:work`, `z:community`, `z:public`) and
//! asserts that a request without a granting capability claim is denied at
//! the `capability_verify` check with the correct FCP reason code.
//!
//! The pipeline is the normative enforcement surface: if this harness ever
//! passes a missing-capability request through to dispatch, that is a
//! default-deny regression.

use fcp_host::{
    EnforcementContext, EnforcementContextBuilder, EnforcementDecision, EnforcementPipeline,
    PipelineOutcome,
};
use fcp_prelude::ZoneId;

const CANONICAL_ZONES: &[fn() -> ZoneId] = &[
    ZoneId::private,
    ZoneId::work,
    ZoneId::community,
    ZoneId::public,
];

/// Build a context that passes every check except (potentially) capability_verify.
///
/// All optional checks (holder proof, checkpoint, revocation, taint, budget,
/// rate) are configured to Skip or Allow so the denial, when it happens, must
/// come from the capability check.
fn ctx(
    zone: &ZoneId,
    capability_claims: Vec<String>,
    required_capability: Option<&str>,
) -> EnforcementContext {
    let mut builder = EnforcementContextBuilder::new()
        .request_id("req-cap-denial")
        .connector_id("slack:utility:1.0.0")
        .operation("send_message")
        .zone_id(zone.as_str())
        .principal("agent-alpha")
        .capability_claims(capability_claims)
        .timestamp_ms(1_700_000_000_000)
        .holder_proof_required(false);
    if let Some(cap) = required_capability {
        builder = builder.required_capability(cap);
    }
    builder.build().expect("valid context")
}

fn evaluate(ctx: EnforcementContext) -> EnforcementDecision {
    EnforcementPipeline::new().evaluate(&ctx)
}

fn assert_cap_denied(decision: &EnforcementDecision, expected_reason: &str, zone: &ZoneId) {
    match &decision.outcome {
        PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } => {
            assert_eq!(
                check_name,
                "capability_verify",
                "zone {}: expected denial at capability_verify, got {}",
                zone.as_str(),
                check_name
            );
            assert_eq!(
                reason_code,
                expected_reason,
                "zone {}: wrong reason code",
                zone.as_str()
            );
        }
        PipelineOutcome::Allow => panic!(
            "zone {}: expected capability denial, pipeline allowed",
            zone.as_str()
        ),
    }
}

#[test]
fn empty_claims_denied_in_every_zone() {
    for make_zone in CANONICAL_ZONES {
        let zone = make_zone();
        let decision = evaluate(ctx(&zone, Vec::new(), Some("messages.write")));
        assert!(!decision.is_allowed(), "zone {}", zone.as_str());
        assert_cap_denied(&decision, "NO_CAPABILITY_CLAIMS", &zone);
    }
}

#[test]
fn non_matching_claim_denied_in_every_zone() {
    for make_zone in CANONICAL_ZONES {
        let zone = make_zone();
        let decision = evaluate(ctx(
            &zone,
            vec!["messages.read".into()],
            Some("messages.write"),
        ));
        assert!(!decision.is_allowed(), "zone {}", zone.as_str());
        assert_cap_denied(&decision, "CAPABILITY_NOT_GRANTED", &zone);
    }
}

#[test]
fn missing_required_capability_denied_in_every_zone() {
    for make_zone in CANONICAL_ZONES {
        let zone = make_zone();
        let decision = evaluate(ctx(&zone, vec!["messages.write".into()], None));
        assert!(!decision.is_allowed(), "zone {}", zone.as_str());
        assert_cap_denied(&decision, "MISSING_REQUIRED_CAPABILITY", &zone);
    }
}

#[test]
fn unrelated_capability_set_denied_in_every_zone() {
    for make_zone in CANONICAL_ZONES {
        let zone = make_zone();
        let decision = evaluate(ctx(
            &zone,
            vec!["files.read".into(), "repos.admin".into()],
            Some("messages.write"),
        ));
        assert!(!decision.is_allowed(), "zone {}", zone.as_str());
        assert_cap_denied(&decision, "CAPABILITY_NOT_GRANTED", &zone);
    }
}

#[test]
fn matching_claim_allows_in_every_zone() {
    for make_zone in CANONICAL_ZONES {
        let zone = make_zone();
        let decision = evaluate(ctx(
            &zone,
            vec!["messages.write".into()],
            Some("messages.write"),
        ));
        assert!(
            decision.is_allowed(),
            "zone {}: matching capability should pass",
            zone.as_str()
        );
    }
}

#[test]
fn wildcard_claim_allows_in_every_zone() {
    for make_zone in CANONICAL_ZONES {
        let zone = make_zone();
        let decision = evaluate(ctx(&zone, vec!["*".into()], Some("messages.write")));
        assert!(
            decision.is_allowed(),
            "zone {}: wildcard capability should pass",
            zone.as_str()
        );
    }
}

#[test]
fn capability_denial_short_circuits_before_later_checks() {
    // capability_verify is check #3 (index 2). A denial there must not execute
    // later checks, so the record list should contain exactly 3 entries:
    // canonical_decode (Allow), zone_membership (Skip), capability_verify (Deny).
    let zone = ZoneId::work();
    let decision = evaluate(ctx(&zone, Vec::new(), Some("messages.write")));
    assert!(!decision.is_allowed());

    assert_eq!(
        decision.checks_run.len(),
        3,
        "capability denial must short-circuit before holder_proof and later",
    );
    let names: Vec<&str> = decision
        .checks_run
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["canonical_decode", "zone_membership", "capability_verify"]
    );
}
