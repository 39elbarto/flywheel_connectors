use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, CapabilityVerifier, FcpError, InstanceId,
    OperationId, ZoneId, CAPABILITY_TOKEN_CLOCK_SKEW_SECS,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;

const CAPABILITY: &str = "cap.matrix";
const OTHER_CAPABILITY: &str = "cap.other";
const OPERATION: &str = "op.matrix";
const OTHER_OPERATION: &str = "op.other";
const WORK_ZONE: &str = "z:work";

fn signing_key(seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[seed; 32]).expect("fixed test key must parse")
}

fn instance_id(value: &str) -> InstanceId {
    value.parse().expect("test instance id must be canonical")
}

fn constraints_cbor(constraints: &CapabilityConstraints) -> Vec<u8> {
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).expect("constraints must serialize");
    cbor
}

fn wildcard_constraints() -> CapabilityConstraints {
    CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    }
}

#[derive(Clone)]
struct TokenSpec<'a> {
    signing_key: &'a Ed25519SigningKey,
    capability: &'a str,
    zone: &'a str,
    audience: Option<&'a str>,
    operation: &'a str,
    target_instance: Option<&'a str>,
    not_before: chrono::DateTime<Utc>,
    expires: chrono::DateTime<Utc>,
    constraints: CapabilityConstraints,
}

fn valid_spec(signing_key: &Ed25519SigningKey) -> TokenSpec<'_> {
    let now = Utc::now();
    TokenSpec {
        signing_key,
        capability: CAPABILITY,
        zone: WORK_ZONE,
        audience: Some(WORK_ZONE),
        operation: OPERATION,
        target_instance: None,
        not_before: now - Duration::minutes(1),
        expires: now + Duration::hours(1),
        constraints: wildcard_constraints(),
    }
}

fn token_from_spec(spec: TokenSpec<'_>) -> CapabilityToken {
    let constraints = constraints_cbor(&spec.constraints);
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(spec.capability)
        .zone_id(spec.zone)
        .principal("user:verifier-matrix")
        .operations(&[spec.operation])
        .issuer("node:verifier-matrix")
        .validity(spec.not_before, spec.expires)
        .try_constraints_cbor(&constraints)
        .expect("test constraints must be valid CBOR");

    if let Some(audience) = spec.audience {
        builder = builder.audience(audience);
    }
    if let Some(instance) = spec.target_instance {
        builder = builder.target_instance(instance);
    }

    let raw = builder.sign(spec.signing_key).expect("token must sign");
    CapabilityToken::from_raw(raw)
}

#[test]
fn capability_verifier_accepts_documented_entrypoint_matrix() {
    let key = signing_key(11);
    let pub_key = key.verifying_key().to_bytes();
    let capability = CapabilityId::from_static(CAPABILITY);
    let operation = OperationId::from_static(OPERATION);
    let instance = instance_id("inst_expected");

    let mut spec = valid_spec(&key);
    spec.target_instance = Some(instance.as_str());
    let token = token_from_spec(spec);

    let bound_verifier = CapabilityVerifier::new(pub_key, ZoneId::work(), instance.clone());
    let bound = bound_verifier
        .verify_bound(token.clone(), &capability, &operation, &[])
        .expect("bound verifier must accept matching instance token");
    assert_eq!(bound.claims().get_capability_id(), Some(CAPABILITY));
    assert_eq!(bound.claims().get_zone_id(), Some(WORK_ZONE));

    let claims = bound_verifier
        .verify_claims(&token, &capability, &operation, &[])
        .expect("by-reference claims verification must share the same predicates");
    assert_eq!(claims.get_capability_id(), Some(CAPABILITY));

    let unbound_verifier = CapabilityVerifier::without_instance_binding(pub_key, ZoneId::work());
    let unbound = unbound_verifier
        .verify_unbound(token.clone(), &capability, &operation, &[])
        .expect("unbound verifier must defer instance matching");
    let promoted = unbound
        .promote_with_instance(&instance)
        .expect("deferred instance predicate must promote with the matching id");
    assert_eq!(promoted.claims().get_capability_id(), Some(CAPABILITY));

    let err = bound_verifier
        .verify_unbound(token.clone(), &capability, &operation, &[])
        .expect_err("bound verifier must not run the unbound entrypoint");
    assert!(
        matches!(err, FcpError::Internal { ref message } if message.contains("verify_unbound")),
        "expected verify_unbound misuse error, got {err:?}"
    );

    let err = unbound_verifier
        .verify_bound(token, &capability, &operation, &[])
        .expect_err("unbound verifier must not run the bound entrypoint");
    assert!(
        matches!(err, FcpError::Internal { ref message } if message.contains("verify_bound")),
        "expected verify_bound misuse error, got {err:?}"
    );
}

enum ExpectedReject {
    InvalidSignature,
    AudienceMismatch,
    ZoneMismatch,
    TokenExpired,
    TokenNotYetValid,
    InstanceMismatch,
    OperationNotGranted,
    EmptyConstraintsDenied,
    ResourceNotAllowed,
}

impl ExpectedReject {
    fn matches(&self, err: &FcpError) -> bool {
        match self {
            Self::InvalidSignature => matches!(err, FcpError::InvalidSignature),
            Self::AudienceMismatch => {
                matches!(err, FcpError::ZoneViolation { message, .. } if message == "Token audience mismatch")
            }
            Self::ZoneMismatch => {
                matches!(err, FcpError::ZoneViolation { message, .. } if message == "Token zone mismatch")
            }
            Self::TokenExpired => matches!(err, FcpError::TokenExpired),
            Self::TokenNotYetValid => matches!(err, FcpError::TokenNotYetValid),
            Self::InstanceMismatch => {
                matches!(err, FcpError::ZoneViolation { message, .. } if message.contains("Token instance mismatch"))
            }
            Self::OperationNotGranted => matches!(err, FcpError::OperationNotGranted { .. }),
            Self::EmptyConstraintsDenied => {
                matches!(err, FcpError::CapabilityDenied { capability, reason } if capability == "constraints" && reason.contains("empty constraint set"))
            }
            Self::ResourceNotAllowed => matches!(err, FcpError::ResourceNotAllowed { .. }),
        }
    }
}

struct MatrixCase {
    name: &'static str,
    token: CapabilityToken,
    verifier: CapabilityVerifier,
    capability: CapabilityId,
    operation: OperationId,
    resources: Vec<String>,
    expected: ExpectedReject,
}

#[test]
fn capability_verifier_rejects_documented_predicate_matrix() {
    let key = signing_key(21);
    let pub_key = key.verifying_key().to_bytes();
    let wrong_key = signing_key(22);
    let now = Utc::now();
    let capability = CapabilityId::from_static(CAPABILITY);
    let operation = OperationId::from_static(OPERATION);
    let expected_instance = instance_id("inst_expected");
    let other_instance = instance_id("inst_other");

    let mut bad_signature = valid_spec(&wrong_key);
    bad_signature.target_instance = Some(expected_instance.as_str());

    let mut wrong_audience = valid_spec(&key);
    wrong_audience.audience = Some("z:project:other");

    let mut wrong_zone = valid_spec(&key);
    wrong_zone.zone = "z:project:other";
    wrong_zone.audience = Some("*");

    let mut expired = valid_spec(&key);
    expired.not_before = now - Duration::hours(2);
    expired.expires = now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 1);

    let mut not_yet_valid = valid_spec(&key);
    not_yet_valid.not_before = now + Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 1);
    not_yet_valid.expires = now + Duration::hours(2);

    let mut instance_mismatch = valid_spec(&key);
    instance_mismatch.target_instance = Some(other_instance.as_str());

    let mut capability_mismatch = valid_spec(&key);
    capability_mismatch.capability = OTHER_CAPABILITY;

    let mut operation_mismatch = valid_spec(&key);
    operation_mismatch.operation = OTHER_OPERATION;

    let mut empty_constraints = valid_spec(&key);
    empty_constraints.constraints = CapabilityConstraints::default();

    let mut resource_mismatch = valid_spec(&key);
    resource_mismatch.constraints = CapabilityConstraints {
        resource_allow: vec!["resource://allowed/*".to_string()],
        ..Default::default()
    };

    let cases = vec![
        MatrixCase {
            name: "invalid_signature",
            token: token_from_spec(bad_signature),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::InvalidSignature,
        },
        MatrixCase {
            name: "wrong_audience",
            token: token_from_spec(wrong_audience),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::AudienceMismatch,
        },
        MatrixCase {
            name: "wrong_zone",
            token: token_from_spec(wrong_zone),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::ZoneMismatch,
        },
        MatrixCase {
            name: "expired",
            token: token_from_spec(expired),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::TokenExpired,
        },
        MatrixCase {
            name: "not_yet_valid",
            token: token_from_spec(not_yet_valid),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::TokenNotYetValid,
        },
        MatrixCase {
            name: "instance_mismatch",
            token: token_from_spec(instance_mismatch),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::InstanceMismatch,
        },
        MatrixCase {
            name: "capability_mismatch",
            token: token_from_spec(capability_mismatch),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::OperationNotGranted,
        },
        MatrixCase {
            name: "operation_mismatch",
            token: token_from_spec(operation_mismatch),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::OperationNotGranted,
        },
        MatrixCase {
            name: "empty_constraints",
            token: token_from_spec(empty_constraints),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance.clone()),
            capability: capability.clone(),
            operation: operation.clone(),
            resources: vec![],
            expected: ExpectedReject::EmptyConstraintsDenied,
        },
        MatrixCase {
            name: "resource_mismatch",
            token: token_from_spec(resource_mismatch),
            verifier: CapabilityVerifier::new(pub_key, ZoneId::work(), expected_instance),
            capability,
            operation,
            resources: vec!["resource://blocked/1".to_string()],
            expected: ExpectedReject::ResourceNotAllowed,
        },
    ];

    for case in cases {
        let err = case
            .verifier
            .verify_bound(
                case.token,
                &case.capability,
                &case.operation,
                &case.resources,
            )
            .unwrap_err();
        assert!(
            case.expected.matches(&err),
            "{}: expected verifier predicate to reject with documented error, got {err:?}",
            case.name
        );
    }
}
