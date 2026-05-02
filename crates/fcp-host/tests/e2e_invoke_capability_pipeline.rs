//! E2E capability-token pipeline through real CapabilityVerifier +
//! real fcp-policy DefaultConstraintEnforcer
//! (testing-perfect-e2e-integration-tests-with-logging-and-no-mocks).
//!
//! AmberLark, 2026-05-02 — alpha-domain coverage sweep.
//!
//! ## What this exercises
//!
//! The full capability-token typestate ladder driven by REAL components:
//!
//! 1. `CapabilityTokenBuilder` mints a real signed COSE/CWT token
//!    (real Ed25519 keypair, real CBOR canonicalization, real signature).
//! 2. Gateway-side `CapabilityVerifier::without_instance_binding` +
//!    `verify_unbound` produces `CapabilityToken<UnboundVerified>`.
//! 3. Connector-side `promote_with_instance` produces
//!    `CapabilityToken<BoundVerified>`.
//! 4. Policy-side `DefaultConstraintEnforcer` evaluates the
//!    `CapabilityConstraints` against a `RequestDescriptor` and
//!    promotes to `CapabilityToken<ConstraintsEnforced>` only when the
//!    constraint set allows the request.
//!
//! Step 4 closes the typestate ladder that the dja9u ratchet protects
//! at the connector boundary. The entire pipeline runs on REAL types
//! end-to-end; no mocks substitute any fcp-host / fcp-policy / fcp-core
//! type. The test asserts each phase's wall-clock budget so a future
//! quadratic regression in the constraint evaluator surfaces as a
//! hard failure.
//!
//! ## No-mock guarantees
//!
//! - REAL `Ed25519SigningKey::generate()` (per-test fresh key, no
//!   recorded signatures or replayed bytes).
//! - REAL `CapabilityTokenBuilder::sign` over REAL canonical CBOR.
//! - REAL `CapabilityVerifier::{without_instance_binding, new}` —
//!   exactly the constructors fcp-host's verify_live_request uses
//!   (per crates/fcp-host/src/bin/fcp-host.rs:2991-3008).
//! - REAL `DefaultConstraintEnforcer` from fcp-policy — exactly the
//!   evaluator that closes the m8j0q.A.6 typestate gap.
//! - No `mockall`, `wiremock`, or hand-rolled fakes for the system
//!   under test.
//!
//! ## Tracing
//!
//! Each phase is wrapped in a `tracing::info_span!`. Per-phase wall-
//! clock budgets are asserted so a future quadratic regression
//! surfaces as a hard test failure (the bead "perf-budget" check).

use std::time::Instant;

use chrono::{Duration, Utc};
use fcp_core::{
    BoundVerified, CapabilityConstraints, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConstraintsEnforced, InstanceId, ObjectId, OperationId, PrincipalId, UnboundVerified,
    ZoneId,
};
use fcp_crypto::{Ed25519SigningKey, cose::CapabilityTokenBuilder};
use fcp_policy::{
    CapabilityConstraintEnforcer, DefaultConstraintEnforcer, RequestDescriptor,
};
use tracing::{Level, info, info_span};

/// Per-phase wall-clock budget. Catches quadratic regressions in the
/// verifier or constraint evaluator.
const PHASE_BUDGET_MS: u128 = 250;

/// Build the canonical test constraints CBOR carrying a single
/// `resource_allow` entry. Same shape used by jkcka_gateway_handoff.
fn test_constraints_cbor(allow_uri: &str) -> Vec<u8> {
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Text("resource_allow".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text(allow_uri.to_string())]),
    )]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).expect("test constraints CBOR encodes");
    bytes
}

fn mk_signed_token(
    signing_key: &Ed25519SigningKey,
    instance: &InstanceId,
    capability_id: &str,
    operation_id: &str,
    zone_str: &str,
    allow_uri: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_str)
        .principal("user:e2e-amberlark")
        .operations(&[operation_id])
        .issuer("node:e2e-gateway")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&test_constraints_cbor(allow_uri))
        .expect("test constraints CBOR is valid")
        .target_instance(instance.as_str())
        .sign(signing_key)
        .expect("sign");
    CapabilityToken::from_raw(cose)
}

fn build_request_descriptor(
    operation_id: &str,
    principal_id: &str,
    resource_uri: &str,
) -> RequestDescriptor {
    RequestDescriptor {
        object_id: ObjectId::from_unscoped_bytes(b"e2e-test-object"),
        operation: OperationId::new(operation_id).expect("operation id"),
        principal: PrincipalId::new(principal_id).expect("principal id"),
        host: "api.example.test".to_string(),
        resource_uri: resource_uri.to_string(),
        requested_at_unix_ms: 1_700_000_000_000,
        observed_calls: 0,
        observed_bytes: 0,
    }
}

#[test]
fn e2e_capability_pipeline_full_typestate_ladder_allow_path() {
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .finish(),
    );
    let scenario_id = "e2e/host/capability-pipeline-allow";
    let capability_id = "cap.e2e.invoke";
    let operation_id = "op.e2e.invoke";
    let zone_str = "z:work";
    let allow_uri = "/v1/e2e/invoke";

    info!(
        scenario_id,
        bead = "AmberLark/e2e",
        "starting full typestate-ladder pipeline test (allow path)"
    );

    // ── Phase 1: real Ed25519 keypair + connector InstanceId ────────
    let phase = info_span!("phase.keygen_and_token_mint").entered();
    let phase_start = Instant::now();

    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let connector_instance = InstanceId::new();
    let token = mk_signed_token(
        &signing_key,
        &connector_instance,
        capability_id,
        operation_id,
        zone_str,
        allow_uri,
    );

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "keygen_and_token_mint phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "keygen_and_token_mint",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    // ── Phase 2: gateway verify_unbound (no instance_id available) ──
    let phase = info_span!("phase.gateway_verify_unbound").entered();
    let phase_start = Instant::now();

    let cap = CapabilityId::new(capability_id).expect("cap id");
    let op = OperationId::new(operation_id).expect("op id");

    let gateway_verifier =
        CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
    let unbound: CapabilityToken<UnboundVerified> = gateway_verifier
        .verify_unbound(token, &cap, &op, &[allow_uri.to_string()])
        .expect("gateway verify_unbound succeeds for valid token");

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "gateway_verify_unbound phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "gateway_verify_unbound",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    // ── Phase 3: connector promote_with_instance ────────────────────
    let phase = info_span!("phase.connector_promote_with_instance").entered();
    let phase_start = Instant::now();

    let bound: CapabilityToken<BoundVerified> = unbound
        .promote_with_instance(&connector_instance)
        .expect("connector promote_with_instance with matching instance");

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "connector_promote_with_instance phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "connector_promote_with_instance",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    // ── Phase 4: policy promote_with_constraints ────────────────────
    let phase = info_span!("phase.policy_promote_with_constraints").entered();
    let phase_start = Instant::now();

    let enforcer = DefaultConstraintEnforcer::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![allow_uri.to_string()],
        ..CapabilityConstraints::default()
    };
    let request = build_request_descriptor(operation_id, "user:e2e-amberlark", allow_uri);

    let enforced: CapabilityToken<ConstraintsEnforced> = bound
        .promote_with_constraints(&enforcer, &constraints, &request)
        .expect("constraint evaluator allows matching request");

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "policy_promote_with_constraints phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "policy_promote_with_constraints",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    // The compiler enforces this at the type level — accepts only
    // ConstraintsEnforced.
    fn execute_constraints_enforced(_token: CapabilityToken<ConstraintsEnforced>) -> bool {
        true
    }
    assert!(execute_constraints_enforced(enforced));

    info!(scenario_id, "test passed");
}

#[test]
fn e2e_capability_pipeline_constraint_mismatch_denies_at_promote() {
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .finish(),
    );
    let scenario_id = "e2e/host/capability-pipeline-deny";
    let capability_id = "cap.e2e.invoke";
    let operation_id = "op.e2e.invoke";
    let zone_str = "z:work";
    let token_allow = "/v1/e2e/invoke";
    let request_uri = "/v1/e2e/UNALLOWED"; // intentionally mismatched

    info!(scenario_id, "starting constraint-mismatch deny test");

    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let instance = InstanceId::new();
    let token = mk_signed_token(
        &signing_key,
        &instance,
        capability_id,
        operation_id,
        zone_str,
        token_allow,
    );
    let cap = CapabilityId::new(capability_id).unwrap();
    let op = OperationId::new(operation_id).unwrap();

    let phase = info_span!("phase.gateway_then_promote").entered();
    let bound = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance.clone())
        .verify_bound(token, &cap, &op, &[token_allow.to_string()])
        .expect("verify_bound succeeds for valid token (the mismatch is at the constraint layer, not signature)");
    drop(phase);

    let phase = info_span!("phase.policy_constraint_mismatch_must_deny").entered();
    let enforcer = DefaultConstraintEnforcer::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![token_allow.to_string()],
        ..CapabilityConstraints::default()
    };
    let mismatched_request = build_request_descriptor(
        operation_id,
        "user:e2e-amberlark",
        request_uri,
    );

    // Pre-check: the standalone evaluator agrees this should DENY.
    let evaluator_outcome = enforcer.evaluate(&constraints, &mismatched_request);
    assert!(
        evaluator_outcome.is_deny(),
        "evaluator must deny constraint mismatch as a sanity floor"
    );

    let denial_err = bound
        .promote_with_constraints(&enforcer, &constraints, &mismatched_request)
        .expect_err("promote_with_constraints MUST refuse a constraint-violating request");

    info!(
        scenario_id,
        phase = "policy_constraint_mismatch_must_deny",
        err = ?denial_err,
        "deny path produced expected error"
    );
    drop(phase);

    info!(scenario_id, "test passed");
}
