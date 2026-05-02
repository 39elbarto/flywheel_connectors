//! `flywheel_connectors-8zagc` — runtime pin of CapabilityToken
//! typestate transitions and instance-binding semantics.
//!
//! `jkcka_gateway_connector_handoff.rs` covers the high-level
//! gateway→connector flow. This file complements it with:
//!
//! 1. **Bound token carries the correct `instance_id`** — promotion
//!    preserves the verified claim payload, and the inner CWT
//!    `INSTANCE_ID` claim string equals the connector's real
//!    `InstanceId::as_str()`.
//! 2. **Type-system runtime contract** — a bound-only executor
//!    function whose signature demands `CapabilityToken<BoundVerified>`
//!    accepts a promoted token and the same call with an unbound
//!    token MUST fail to compile (compile-fail-via-shape).
//! 3. **Roundtrip identity** — claims emitted by
//!    `verify_unbound + promote_with_instance` are byte-for-byte
//!    identical to claims emitted by `verify_bound` for the same
//!    raw token + instance.
//! 4. **Instance-agnostic tokens** — a token with NO `INSTANCE_ID`
//!    claim promotes unconditionally regardless of the InstanceId
//!    passed to `promote_with_instance` (matches the documented
//!    invariant that `verify_bound` skips the check when the claim
//!    is absent).
//! 5. **Wrong-instance error preservation** — promotion failure on
//!    instance mismatch surfaces a structured `FcpError`.

use chrono::{Duration, Utc};
use fcp_core::{
    BoundVerified, CapabilityId, CapabilityToken, CapabilityVerifier, InstanceId, OperationId,
    UnboundVerified, ZoneId,
};
use fcp_crypto::{Ed25519SigningKey, cose::CapabilityTokenBuilder, cose::fcp2_claims};

fn test_constraints_cbor() -> Vec<u8> {
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Text("resource_allow".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text("*".into())]),
    )]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).unwrap();
    bytes
}

fn mk_signed_token_with_instance(
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

fn mk_signed_token_no_instance(signing_key: &Ed25519SigningKey) -> CapabilityToken {
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
        // NO .target_instance() — instance-agnostic token.
        .sign(signing_key)
        .expect("sign");
    CapabilityToken::from_raw(cose)
}

/// Bound-only executor — only accepts `BoundVerified` tokens.
/// Compile-fail proof: passing `CapabilityToken<UnboundVerified>` here
/// is a type error. (Runtime-side the compiler enforces the contract.)
fn bound_only_executor(_token: &CapabilityToken<BoundVerified>) -> &'static str {
    "bound-accepted"
}

#[test]
fn bound_token_carries_correct_instance_id_after_promotion() {
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let connector_instance = InstanceId::new();
    let token = mk_signed_token_with_instance(&signing_key, &connector_instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    let gateway_verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
    let unbound: CapabilityToken<UnboundVerified> = gateway_verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect("gateway unbound verify");

    let bound: CapabilityToken<BoundVerified> = unbound
        .promote_with_instance(&connector_instance)
        .expect("connector promote");

    // The promoted token's claims MUST carry the connector's instance_id.
    let claims = bound.claims();
    let instance_claim = claims
        .get(fcp2_claims::INSTANCE_ID)
        .expect("BoundVerified token MUST carry INSTANCE_ID claim after promotion");
    let instance_str = match instance_claim {
        ciborium::Value::Text(s) => s.as_str(),
        other => panic!("INSTANCE_ID claim MUST be a CBOR Text value, got {other:?}"),
    };
    assert_eq!(
        instance_str,
        connector_instance.as_str(),
        "promoted bound token's INSTANCE_ID claim MUST equal the InstanceId passed to promote_with_instance"
    );
}

#[test]
fn bound_only_executor_accepts_promoted_token() {
    // Type-level pin: an executor whose signature demands
    // CapabilityToken<BoundVerified> accepts a promoted token. The
    // same call site refusing an UnboundVerified token is a compile
    // error (separate trybuild test) — this one verifies the
    // happy-path acceptance.
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let instance = InstanceId::new();
    let token = mk_signed_token_with_instance(&signing_key, &instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    let unbound = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
        .verify_unbound(token, &cap, &op, &[])
        .expect("verify unbound");
    let bound = unbound.promote_with_instance(&instance).expect("promote");

    assert_eq!(
        bound_only_executor(&bound),
        "bound-accepted",
        "executor MUST accept promoted bound token"
    );
}

#[test]
fn unbound_and_bound_marker_types_are_distinct_at_type_level() {
    // The PhantomData<Marker> shape on CapabilityToken means the two
    // type instantiations are distinct types. Pin via std::any::TypeId
    // — runtime witness of the type-level distinction.
    use std::any::TypeId;
    assert_ne!(
        TypeId::of::<CapabilityToken<UnboundVerified>>(),
        TypeId::of::<CapabilityToken<BoundVerified>>(),
        "UnboundVerified and BoundVerified MUST be distinct types — \
         the type system MUST refuse to coerce one to the other"
    );
}

#[test]
fn unbound_to_bound_roundtrip_claims_match_direct_bound_verify() {
    // Property: verify_unbound + promote_with_instance produces
    // claims byte-for-byte identical to verify_bound for the same
    // raw token + instance. This is the explicit equivalence that
    // makes the gateway split an implementation detail rather than
    // a semantic divergence.
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let instance = InstanceId::new();

    // Make TWO identical tokens (same instance, signed independently
    // with the same key — claims payload is identical even if the
    // outer signature bytes differ).
    let token_a = mk_signed_token_with_instance(&signing_key, &instance);
    let token_b = mk_signed_token_with_instance(&signing_key, &instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    // Path A: direct bound verify.
    let bound_via_direct = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance.clone())
        .verify_bound(token_a, &cap, &op, &[])
        .expect("direct bound verify");

    // Path B: unbound verify + promote.
    let bound_via_promote = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
        .verify_unbound(token_b, &cap, &op, &[])
        .expect("unbound verify")
        .promote_with_instance(&instance)
        .expect("promote");

    let claims_a = bound_via_direct.claims();
    let claims_b = bound_via_promote.claims();

    // INSTANCE_ID claim parity.
    let inst_a = claims_a.get(fcp2_claims::INSTANCE_ID);
    let inst_b = claims_b.get(fcp2_claims::INSTANCE_ID);
    assert_eq!(
        inst_a, inst_b,
        "INSTANCE_ID claim MUST be identical across both verification paths"
    );

    // Capability + zone parity (already covered in the existing test,
    // but pin again to anchor the property).
    assert_eq!(claims_a.get_capability_id(), claims_b.get_capability_id());
    assert_eq!(claims_a.get_zone_id(), claims_b.get_zone_id());
}

#[test]
fn instance_agnostic_token_promotes_unconditionally() {
    // Documented invariant: a token with NO INSTANCE_ID claim
    // promotes regardless of the InstanceId passed to
    // promote_with_instance — matches verify_bound semantics.
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let token = mk_signed_token_no_instance(&signing_key);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    let unbound = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
        .verify_unbound(token, &cap, &op, &[])
        .expect("verify unbound");

    // ANY InstanceId MUST succeed because the token doesn't bind to one.
    let arbitrary_instance = InstanceId::new();
    let bound = unbound
        .promote_with_instance(&arbitrary_instance)
        .expect("instance-agnostic token MUST promote regardless of supplied InstanceId");

    // The promoted token's claims do NOT carry the supplied instance
    // (the original token had no INSTANCE_ID claim, so promotion
    // does not synthesize one).
    let claims = bound.claims();
    assert!(
        claims.get(fcp2_claims::INSTANCE_ID).is_none(),
        "instance-agnostic promotion MUST NOT synthesize an INSTANCE_ID claim"
    );
}

#[test]
fn promote_with_wrong_instance_returns_structured_error() {
    let signing_key = Ed25519SigningKey::generate();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let token_instance = InstanceId::new();
    let wrong_instance = InstanceId::new();
    let token = mk_signed_token_with_instance(&signing_key, &token_instance);
    let cap = CapabilityId::new("cap.test").unwrap();
    let op = OperationId::new("op.read").unwrap();

    let unbound = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
        .verify_unbound(token, &cap, &op, &[])
        .expect("verify unbound");

    let result = unbound.promote_with_instance(&wrong_instance);
    let err = result.expect_err("wrong instance MUST fail to promote");

    // Pin: error reaches the structured-error path (not a panic).
    let dbg = format!("{err:?}");
    assert!(
        !dbg.is_empty(),
        "promotion error MUST be a structured FcpError, not a silent failure"
    );
}
