//! Capability-token instance-binding promote conformance.
//!
//! `CapabilityToken<UnboundVerified>::promote_with_instance` is the
//! gateway -> connector handoff: the gateway runs `verify_unbound`
//! (it does not know the connector's `InstanceId`); the connector
//! runtime then calls `promote_with_instance` with its own id and
//! gets back a `BoundVerified` token.
//!
//! The documented contract (capability.rs:1269) has THREE branches:
//!
//! 1. Token declares `instance_id` matching `expected` → promoted.
//! 2. Token declares `instance_id` NOT matching `expected` → rejected
//!    with `FcpError::ZoneViolation` whose message names both the
//!    expected and actual instance ids.
//! 3. Token has NO `instance_id` claim → promoted unconditionally.
//!    Legacy "universally applicable" semantics, intentionally
//!    aligned with `CapabilityVerifier::new(...).verify_bound()`'s
//!    behaviour when the claim is absent.
//!
//! `crates/fcp-host/tests/jkcka_gateway_connector_handoff.rs` covers
//! (1) and (2) but NOT (3). And the consuming `self` signature on
//! `promote_with_instance` is a typestate-level replay defense worth
//! pinning at the conformance layer too: a single `UnboundVerified`
//! token can only be promoted once, so a captured token cannot be
//! reused at multiple instances.
//!
//! Cross-path equivalence (br-jkcka): `verify_bound` directly
//! produces a `BoundVerified` whose verified claims must match
//! `verify_unbound + promote_with_instance`. The two execution
//! paths converge on the same enforcement.

use chrono::{Duration, Utc};
use ciborium::Value as CborValue;
use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_prelude::{
    BoundVerified, CapabilityId, CapabilityToken, CapabilityVerifier, FcpError, InstanceId,
    OperationId, UnboundVerified, ZoneId,
};

fn wildcard_constraints_cbor() -> Vec<u8> {
    let map = CborValue::Map(vec![(
        CborValue::Text("resource_allow".into()),
        CborValue::Array(vec![CborValue::Text("*".into())]),
    )]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).expect("encode constraints");
    bytes
}

/// Build a token bound to a specific instance.
fn build_bound_token(signing_key: &Ed25519SigningKey, instance: &InstanceId) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("cap.test")
        .zone_id(ZoneId::work().as_str())
        .principal("user:test")
        .operations(&["op.read"])
        .issuer("node:gateway")
        .validity(now - Duration::minutes(1), now + Duration::hours(1))
        .try_constraints_cbor(&wildcard_constraints_cbor())
        .expect("constraints CBOR")
        .target_instance(instance.as_str())
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

/// Build an instance-agnostic token (no `target_instance` claim).
fn build_agnostic_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("cap.test")
        .zone_id(ZoneId::work().as_str())
        .principal("user:test")
        .operations(&["op.read"])
        .issuer("node:gateway")
        .validity(now - Duration::minutes(1), now + Duration::hours(1))
        .try_constraints_cbor(&wildcard_constraints_cbor())
        .expect("constraints CBOR")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

fn unbound_verifier(signing_key: &Ed25519SigningKey) -> CapabilityVerifier {
    CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    )
}

fn cap() -> CapabilityId {
    CapabilityId::new("cap.test").expect("capability id")
}

fn op() -> OperationId {
    OperationId::new("op.read").expect("operation id")
}

#[test]
fn promote_succeeds_when_instance_id_matches() {
    let signing_key = Ed25519SigningKey::generate();
    let instance = InstanceId::new();
    let token = build_bound_token(&signing_key, &instance);
    let verifier = unbound_verifier(&signing_key);

    let unbound: CapabilityToken<UnboundVerified> = verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("gateway-vantage verify");

    let bound: CapabilityToken<BoundVerified> = unbound
        .promote_with_instance(&instance)
        .expect("matching instance id must promote to BoundVerified");

    assert_eq!(
        bound.claims().get_capability_id(),
        Some("cap.test"),
        "promoted bound token must carry the same capability_id claim"
    );
}

#[test]
fn promote_rejects_mismatched_instance_with_zone_violation() {
    let signing_key = Ed25519SigningKey::generate();
    let token_instance = InstanceId::new();
    let wrong_instance = InstanceId::new();
    let token = build_bound_token(&signing_key, &token_instance);
    let verifier = unbound_verifier(&signing_key);

    let unbound = verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("gateway-vantage verify");

    let err = unbound
        .promote_with_instance(&wrong_instance)
        .expect_err("mismatched instance id must reject promote");
    match err {
        FcpError::ZoneViolation { message, .. } => {
            assert!(
                message.contains("instance mismatch"),
                "ZoneViolation message must surface the instance-mismatch reason; got {message:?}"
            );
            assert!(
                message.contains(token_instance.as_str()),
                "ZoneViolation message must name the token's claimed instance ({}) so callers can route correctly; got {message:?}",
                token_instance.as_str()
            );
            assert!(
                message.contains(wrong_instance.as_str()),
                "ZoneViolation message must name the expected instance ({}) so callers can correlate; got {message:?}",
                wrong_instance.as_str()
            );
        }
        other => panic!("expected ZoneViolation, got {other:?}"),
    }
}

#[test]
fn instance_agnostic_token_promotes_unconditionally() {
    // NORMATIVE behaviour (capability.rs:1274 case 3): a token with
    // NO instance_id claim promotes against ANY connector instance.
    // This is the "legacy universally-applicable" semantics that
    // mirrors verify_bound's behaviour when the claim is absent.
    // Pin it explicitly so a future tightening (e.g., requiring
    // instance_id) is a deliberate breaking change rather than a
    // silent regression.
    let signing_key = Ed25519SigningKey::generate();
    let token = build_agnostic_token(&signing_key);
    let verifier = unbound_verifier(&signing_key);

    let unbound = verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("instance-agnostic token verifies at gateway vantage");

    // Promoting with an arbitrary instance id MUST succeed because
    // the token did not declare one.
    let arbitrary_instance = InstanceId::new();
    unbound
        .promote_with_instance(&arbitrary_instance)
        .expect("instance-agnostic token must promote against any instance");
}

#[test]
fn instance_agnostic_token_promotes_against_two_different_instances_independently() {
    // Strengthens the prior test: an instance-agnostic token has no
    // implicit binding to the FIRST instance it is promoted against.
    // Two independent verify_unbound passes against the same token
    // must each produce a token that promotes to a different
    // instance.
    let signing_key = Ed25519SigningKey::generate();
    let verifier = unbound_verifier(&signing_key);

    let token_a = build_agnostic_token(&signing_key);
    let unbound_a = verifier
        .verify_unbound(token_a, &cap(), &op(), &[])
        .expect("verify_unbound A");
    let inst_a = InstanceId::new();
    unbound_a
        .promote_with_instance(&inst_a)
        .expect("promote against instance A");

    let token_b = build_agnostic_token(&signing_key);
    let unbound_b = verifier
        .verify_unbound(token_b, &cap(), &op(), &[])
        .expect("verify_unbound B");
    let inst_b = InstanceId::new();
    assert_ne!(inst_a.as_str(), inst_b.as_str(), "fixture sanity");
    unbound_b
        .promote_with_instance(&inst_b)
        .expect("instance-agnostic token must promote independently to a different instance");
}

#[test]
fn verify_bound_and_unbound_then_promote_yield_equivalent_claims() {
    // Cross-path equivalence (br-jkcka): the direct verify_bound
    // path and the unbound + promote path must agree on the
    // verified claims for an instance-bound token. Without this,
    // gateway and connector vantages would enforce different
    // policies.
    let signing_key = Ed25519SigningKey::generate();
    let instance = InstanceId::new();
    let pub_bytes = signing_key.verifying_key().to_bytes();

    // Path A: verify_bound directly.
    let token_a = build_bound_token(&signing_key, &instance);
    let bound_verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance.clone());
    let via_bound = bound_verifier
        .verify_bound(token_a, &cap(), &op(), &[])
        .expect("direct bound verify");

    // Path B: verify_unbound then promote.
    let token_b = build_bound_token(&signing_key, &instance);
    let via_promote = unbound_verifier(&signing_key)
        .verify_unbound(token_b, &cap(), &op(), &[])
        .expect("verify_unbound")
        .promote_with_instance(&instance)
        .expect("promote");

    assert_eq!(
        via_bound.claims().get_capability_id(),
        via_promote.claims().get_capability_id(),
        "both paths must converge on the same capability_id"
    );
    assert_eq!(
        via_bound.claims().get_zone_id(),
        via_promote.claims().get_zone_id(),
        "both paths must converge on the same zone_id"
    );
}

#[test]
fn promoted_bound_token_carries_underlying_unbound_claims() {
    // The promotion path is purely a typestate transition; the
    // underlying claims do not change. This locks the property
    // that downstream callers can rely on the promoted token to
    // carry exactly the claims that were verified at gateway
    // vantage.
    let signing_key = Ed25519SigningKey::generate();
    let instance = InstanceId::new();
    let token = build_bound_token(&signing_key, &instance);
    let verifier = unbound_verifier(&signing_key);

    let unbound = verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("verify_unbound");
    let unbound_capability = unbound.claims().get_capability_id().map(str::to_string);
    let unbound_zone = unbound.claims().get_zone_id().map(str::to_string);

    let bound = unbound.promote_with_instance(&instance).expect("promote");

    assert_eq!(
        bound.claims().get_capability_id().map(str::to_string),
        unbound_capability,
        "promote_with_instance must NOT mutate verified claims"
    );
    assert_eq!(
        bound.claims().get_zone_id().map(str::to_string),
        unbound_zone,
        "promote_with_instance must preserve zone_id"
    );
}

#[test]
fn instance_mismatch_message_is_zone_violation_not_invalid_signature() {
    // The mismatch error variant is ZoneViolation rather than
    // InvalidSignature. This is a contract callers depend on for
    // routing — a ZoneViolation tells the operator "wrong scope, try
    // a different one"; an InvalidSignature would imply a security
    // compromise. The variant mapping must NOT regress.
    let signing_key = Ed25519SigningKey::generate();
    let token = build_bound_token(&signing_key, &InstanceId::new());
    let verifier = unbound_verifier(&signing_key);

    let unbound = verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("verify_unbound");
    let err = unbound
        .promote_with_instance(&InstanceId::new())
        .expect_err("mismatched promote must error");

    assert!(
        matches!(err, FcpError::ZoneViolation { .. }),
        "mismatched promote MUST surface ZoneViolation (not InvalidSignature); got {err:?}"
    );
}
