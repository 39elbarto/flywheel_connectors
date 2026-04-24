//! jkcka.5 — End-to-end gateway → connector instance-binding handoff.
//!
//! Exercises the two-phase verification model made visible in types
//! by jkcka.3:
//!
//! 1. Gateway (vantage: does NOT know the connector's real `InstanceId`)
//!    calls `verify_unbound`, producing `CapabilityToken<UnboundVerified>`.
//! 2. Token is serialized-ish and crosses the gateway→connector boundary.
//!    (Modeled here as passing ownership via the transport boundary;
//!    real fcp-host uses the request channel.)
//! 3. Connector runtime (vantage: DOES know its real `InstanceId`)
//!    calls `promote_with_instance`, producing
//!    `CapabilityToken<BoundVerified>`.
//! 4. An operation-executor-shaped function that requires
//!    `CapabilityToken<BoundVerified>` accepts the promoted token.
//!
//! These tests guard against a regression where `verify_unbound` /
//! `promote_with_instance` semantics silently diverge from the
//! verify-bound-directly path.

use chrono::{Duration, Utc};
use fcp_core::{
    BoundVerified, CapabilityId, CapabilityToken, CapabilityVerifier, InstanceId, OperationId,
    UnboundVerified, ZoneId,
};
use fcp_crypto::{Ed25519SigningKey, cose::CapabilityTokenBuilder};

/// Build the canonical test constraints CBOR (resource_allow = ["*"]).
fn test_constraints_cbor() -> Vec<u8> {
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Text("resource_allow".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text("*".into())]),
    )]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).unwrap();
    bytes
}

/// Simulates the operation-executor. After jkcka.4/jkcka.8 migrate
/// the rest of the workspace, real executors (connector runtimes,
/// sandbox spawners, admin-mutation paths) will have this signature.
fn execute_bound_op(_token: CapabilityToken<BoundVerified>, _op: &OperationId) -> bool {
    true
}

fn mk_signed_token(
    signing_key: &Ed25519SigningKey,
    instance: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("cap.test")
        .zone_id("z:work")
        .principal("user:alice")
        .operations(&["op.read"])
        .issuer("node:gateway")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&test_constraints_cbor())
        .expect("test constraints CBOR should be valid")
        .target_instance(instance.as_str())
        .sign(signing_key)
        .expect("sign");
    CapabilityToken::from_raw(cose)
}

#[test]
fn gateway_to_connector_handoff_end_to_end() {
    // Arrange: gateway key + connector's real instance id.
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let connector_instance = InstanceId::new();
    let token = mk_signed_token(&signing_key, &connector_instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    // Phase 1: gateway vantage (no connector InstanceId known).
    let gateway_verifier =
        CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
    let unbound: CapabilityToken<UnboundVerified> = gateway_verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect("gateway unbound verify");

    // (Transport step — in production the token crosses to the
    // connector process. Here we just hold ownership.)

    // Phase 2: connector vantage (knows its own InstanceId).
    let bound: CapabilityToken<BoundVerified> = unbound
        .promote_with_instance(&connector_instance)
        .expect("connector promote");

    // Phase 3: executor demands the bound variant. Type-level enforced.
    assert!(execute_bound_op(bound, &op));
}

#[test]
fn gateway_handoff_rejects_wrong_connector_instance() {
    // Arrange as above, but the connector "claims" a different instance.
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let token_instance = InstanceId::new();
    let wrong_connector_instance = InstanceId::new();
    let token = mk_signed_token(&signing_key, &token_instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    let gateway_verifier =
        CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
    let unbound = gateway_verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect("gateway unbound verify");

    // Promote with the WRONG instance — must error.
    let err = unbound
        .promote_with_instance(&wrong_connector_instance)
        .expect_err("wrong instance must reject");
    // Any error is acceptable; we just want promotion refused.
    let message = format!("{err:?}");
    assert!(
        message.contains("mismatch") || message.contains("ZoneViolation"),
        "promotion error must reference the mismatch; got: {message}"
    );
}

#[test]
fn direct_bound_verify_matches_unbound_plus_promote() {
    // Property: issuing + verifying in one step (CapabilityVerifier::new
    // + verify_bound) produces a token whose claims are identical to
    // the one obtained via verify_unbound → promote_with_instance.
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let instance = InstanceId::new();
    let token_a = mk_signed_token(&signing_key, &instance);
    let token_b = mk_signed_token(&signing_key, &instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    // Path A: direct bound verify
    let bound_verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance.clone());
    let via_bound = bound_verifier
        .verify_bound(token_a, &cap, &op, &[])
        .expect("direct bound verify");

    // Path B: unbound verify then promote
    let unbound_verifier =
        CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
    let via_promote = unbound_verifier
        .verify_unbound(token_b, &cap, &op, &[])
        .expect("unbound verify")
        .promote_with_instance(&instance)
        .expect("promote");

    // Both paths produce tokens whose verified claims match on the
    // essential fields (capability_id, zone_id).
    assert_eq!(
        via_bound.claims().get_capability_id(),
        via_promote.claims().get_capability_id()
    );
    assert_eq!(
        via_bound.claims().get_zone_id(),
        via_promote.claims().get_zone_id()
    );
}
