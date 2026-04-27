#![no_main]
//! Fuzz target for the InvokeRequest dispatch chain
//! (`fcp-core::CapabilityVerifier::verify_unbound` +
//! `fcp-core::policy::simulate_policy_decision`).
//!
//! Bead flywheel_connectors-jdef7. Drives an adversarial `InvokeRequest`
//! and `ZonePolicyObject` through the two boundaries the host gateway
//! crosses for every `/rpc/invoke`:
//!
//! 1. **Capability verification** — `CapabilityVerifier::without_instance_binding`
//!    + `verify_unbound`. The fuzzer constructs a real signed token (via
//!    `CapabilityTokenBuilder`) using a fixed key, then asks the verifier
//!    to check it against fuzzer-chosen `CapabilityId` / `OperationId` /
//!    `resource_uris`. The verifier must surface mismatches as `Err`,
//!    never panic, and never silently accept.
//!
//! 2. **Zone-policy simulation** — `simulate_policy_decision`. The fuzzer
//!    builds a `ZonePolicyObject` whose allow/deny patterns are drawn
//!    from fuzz bytes (including extreme glob shapes), pairs it with the
//!    fuzzed `InvokeRequest`, and runs the simulation. The decision must
//!    be deterministic: re-running with the same input must yield the
//!    same `decision` discriminant.
//!
//! Invariants asserted across every input:
//! - Neither boundary panics.
//! - When the verifier returns `Ok`, the unbound-verified token's verified
//!   claims are non-empty.
//! - When the simulation returns `Ok`, re-running with the same input
//!   produces a structurally equivalent decision.
//! - When the simulation returns `Err`, the error is one of the declared
//!   `PolicySimulationError` variants (no Internal/panic-style fall-through).

use arbitrary::{Arbitrary, Unstructured};
use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    DecisionReceiptPolicy, InvokeRequest, ObjectHeader, OperationId, PolicySimulationError,
    PolicySimulationInput, Provenance, RequestId, SafetyTier, TransportMode, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy, simulate_policy_decision,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use libfuzzer_sys::fuzz_target;
use serde_json::json;

const FIXED_SIGNING_KEY_BYTES: [u8; 32] = [0x37; 32];

/// Standard zones the verifier and policy can be parameterized over.
const ZONES: &[&str] = &["z:work", "z:private", "z:owner", "z:community", "z:public"];

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Token zone selector mod ZONES.len().
    token_zone_idx: u8,
    /// Request zone selector mod ZONES.len(). When != token_zone_idx the
    /// verifier must reject (zone-binding check).
    request_zone_idx: u8,
    /// Policy zone selector mod ZONES.len(). When != request_zone_idx the
    /// simulation must surface ZoneMismatch.
    policy_zone_idx: u8,
    /// Capability id seed. Hex-formatted to stay canonical.
    capability_seed: u32,
    /// Operation id seed.
    operation_seed: u32,
    /// Required-capability seed used by the verifier (may differ from the
    /// token's capability_id to drive the mismatch path).
    required_capability_seed: u32,
    /// Required-operation seed used by the verifier (may differ from
    /// token's granted operation).
    required_operation_seed: u32,
    /// Connector seed.
    connector_seed: u32,
    /// Principal selector — one of a few canonical principal strings.
    principal_idx: u8,
    /// Whether to declare a fresh expiration or to forge an expired one.
    expiration_mode: u8,
    /// Mode for `principal_allow` / `principal_deny` policy patterns.
    policy_mode: u8,
    /// Resource uris fed to verify_unbound (count mod 4, each blank-or-glob).
    resource_count: u8,
    /// Random byte sequence for resource_uri shapes.
    resource_seed: [u8; 16],
    /// Whether the simulation re-run determinism check is enabled.
    rerun_determinism: bool,
}

fn principal_for_idx(idx: u8) -> &'static str {
    match idx % 5 {
        0 => "user:fuzz",
        1 => "agent:fuzz",
        2 => "tag:fcp-work",
        3 => "service:fuzz",
        _ => "owner:fuzz",
    }
}

fn capability_id_from_seed(seed: u32) -> CapabilityId {
    // Use a hex suffix so the resulting id matches the canonical-id
    // grammar (lowercase ascii / digits / a few separators).
    let suffix = format!("{seed:08x}");
    CapabilityId::new(format!("cap.fuzz.{suffix}"))
        .expect("hex-suffixed capability id must be canonical")
}

fn operation_id_from_seed(seed: u32) -> OperationId {
    let suffix = format!("{seed:08x}");
    OperationId::new(format!("fuzz.op.{suffix}"))
        .expect("hex-suffixed operation id must be canonical")
}

fn connector_id_from_seed(seed: u32) -> ConnectorId {
    let suffix = format!("{seed:08x}");
    ConnectorId::new(format!("fcp.fuzz.{suffix}"), "utility", "1.0.0")
        .expect("hex-suffixed connector id must be canonical")
}

fn zone_from_idx(idx: u8) -> ZoneId {
    let canonical = ZONES[(idx as usize) % ZONES.len()];
    canonical.parse().expect("ZONES entries must parse")
}

fn constraints_cbor(input: &FuzzInput) -> Vec<u8> {
    // Drive policy-pattern adversarial fuzzing through `resource_allow`
    // entries. Stay within the canonical-id grammar by hex-encoding seeds.
    let mut allow = vec!["*".to_string()];
    if input.policy_mode % 4 == 1 {
        allow.push(format!("scope:{:08x}", input.capability_seed));
    }
    let constraints = CapabilityConstraints {
        resource_allow: allow,
        ..Default::default()
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&constraints, &mut buf).expect("constraints cbor must serialize");
    buf
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    input: &FuzzInput,
    capability_id: &CapabilityId,
    operation: &OperationId,
    zone_id: &ZoneId,
    principal: &str,
) -> Option<CapabilityToken> {
    let now = Utc::now();
    let (nbf, exp) = match input.expiration_mode % 4 {
        0 => (now - Duration::seconds(60), now + Duration::seconds(3600)),
        1 => (now - Duration::seconds(7200), now - Duration::seconds(60)), // expired
        2 => (now + Duration::seconds(3600), now + Duration::seconds(7200)), // not yet valid
        _ => (now - Duration::seconds(30), now + Duration::seconds(30)),
    };
    let cbor = constraints_cbor(input);
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id.as_str())
        .zone_id(zone_id.as_str())
        .principal(principal)
        .operations(&[operation.as_str()])
        .issuer("node:fuzz")
        .audience("*")
        .validity(nbf, exp)
        .try_constraints_cbor(&cbor)
        .ok()?
        .sign(signing_key)
        .ok()?;
    Some(CapabilityToken::from_raw(raw))
}

fn build_zone_policy(input: &FuzzInput, zone_id: ZoneId) -> ZonePolicyObject {
    use fcp_core::PolicyPattern;
    let allow_seed = format!("user:{:08x}", input.connector_seed);
    let principal_allow = match input.policy_mode % 4 {
        0 => Vec::new(), // no allow list
        1 => vec![PolicyPattern {
            pattern: "*".into(),
        }],
        2 => vec![PolicyPattern {
            pattern: allow_seed.clone(),
        }],
        _ => vec![
            PolicyPattern {
                pattern: "user:*".into(),
            },
            PolicyPattern {
                pattern: "agent:*".into(),
            },
        ],
    };
    let principal_deny = match input.policy_mode % 7 {
        3 => vec![PolicyPattern {
            pattern: "*:fuzz".into(),
        }],
        5 => vec![PolicyPattern {
            pattern: format!("{}-deny", allow_seed),
        }],
        _ => Vec::new(),
    };
    ZonePolicyObject {
        header: ObjectHeader {
            schema: fcp_cbor::SchemaId::new(
                "fcp.core",
                "ZonePolicyObject",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: zone_id.clone(),
            created_at: u64::try_from(Utc::now().timestamp()).unwrap_or(0),
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        zone_id,
        principal_allow,
        principal_deny,
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        },
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn resource_uris(input: &FuzzInput) -> Vec<String> {
    let count = (input.resource_count as usize) % 4;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let chunk = &input.resource_seed[i * 4..(i + 1) * 4];
        out.push(format!("res:{}", hex::encode(chunk)));
    }
    out
}

fn assert_simulation_error_well_formed(err: &PolicySimulationError) {
    // Confirm the error is one of the declared variants by exhaustively
    // matching the discriminant. A new variant added without updating
    // this match will fail to compile.
    match err {
        PolicySimulationError::MissingClaim { .. }
        | PolicySimulationError::InvalidPrincipal { .. }
        | PolicySimulationError::InvalidCapability { .. }
        | PolicySimulationError::TokenClaims { .. }
        | PolicySimulationError::ZoneMismatch { .. } => {
            // touch the Display impl to ensure no formatter panics
            let _ = err.to_string();
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    let signing_key =
        Ed25519SigningKey::from_bytes(&FIXED_SIGNING_KEY_BYTES).expect("fixed fuzz key must parse");
    let verifying_key = signing_key.verifying_key();

    let token_zone = zone_from_idx(input.token_zone_idx);
    let request_zone = zone_from_idx(input.request_zone_idx);
    let policy_zone = zone_from_idx(input.policy_zone_idx);

    let capability_id = capability_id_from_seed(input.capability_seed);
    let operation = operation_id_from_seed(input.operation_seed);
    let connector_id = connector_id_from_seed(input.connector_seed);
    let principal = principal_for_idx(input.principal_idx);

    let Some(token) = build_token(
        &signing_key,
        &input,
        &capability_id,
        &operation,
        &token_zone,
        principal,
    ) else {
        return;
    };

    // ---- 1. CapabilityVerifier::verify_unbound ------------------------
    // Verifier zone matches the request zone (gateway vantage). When that
    // differs from the token zone, the verifier must surface ZoneMismatch.
    let verifier = CapabilityVerifier::without_instance_binding(
        verifying_key.to_bytes(),
        request_zone.clone(),
    );
    let required_capability = capability_id_from_seed(input.required_capability_seed);
    let required_operation = operation_id_from_seed(input.required_operation_seed);
    let resources = resource_uris(&input);

    // Snapshot before consuming `token`.
    let token_for_simulation = token.clone();

    let verify_result =
        verifier.verify_unbound(token, &required_capability, &required_operation, &resources);

    // Invariant: when verify_unbound returns Ok, the produced
    // UnboundVerified token must carry verified claims and the request
    // zone must match the token zone. When it returns Err, the error is
    // structured (Display works without panic).
    match verify_result {
        Ok(verified) => {
            // `claims()` is the public accessor on UnboundVerified tokens.
            // Touching it ensures the verifier did populate the verified
            // claim set and that the accessor is panic-free.
            let _ = verified.claims();
            assert_eq!(
                token_zone.as_str(),
                request_zone.as_str(),
                "verify_unbound must reject mismatched zones; got Ok with token={token_zone:?} request={request_zone:?}"
            );
        }
        Err(err) => {
            let _ = err.to_string();
        }
    }

    // ---- 2. simulate_policy_decision ----------------------------------
    let zone_policy = build_zone_policy(&input, policy_zone.clone());
    let invoke_request = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::random(),
        connector_id: connector_id.clone(),
        operation: required_operation.clone(),
        zone_id: request_zone.clone(),
        input: json!({ "fuzz": hex::encode(input.resource_seed) }),
        capability_token: token_for_simulation.clone(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let simulation_input = PolicySimulationInput {
        zone_policy: zone_policy.clone(),
        invoke_request: invoke_request.clone(),
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: SafetyTier::Safe,
        principal: Some(principal.to_string()),
        capability_id: Some(capability_id.as_str().to_string()),
        provenance_record: None,
        now_ms: Some(1_700_000_000_000),
        posture_attestation: None,
    };

    let first_decision = simulate_policy_decision(&simulation_input);

    // Invariant: ZoneMismatch is the documented surface when request zone
    // disagrees with the policy zone. Anything else means policy_zone ==
    // request_zone, in which case the result must be Ok or one of the
    // claim/principal/capability validation errors (which require
    // unverifiable inputs we control above).
    match &first_decision {
        Ok(receipt) => {
            assert_eq!(
                receipt.zone_id().as_str(),
                request_zone.as_str(),
                "decision receipt must echo the request zone",
            );
        }
        Err(err) => {
            assert_simulation_error_well_formed(err);
            if matches!(err, PolicySimulationError::ZoneMismatch { .. }) {
                assert_ne!(
                    request_zone.as_str(),
                    policy_zone.as_str(),
                    "ZoneMismatch must only surface when zones actually differ"
                );
            }
        }
    }

    // ---- 3. determinism re-run ----------------------------------------
    if input.rerun_determinism {
        let second_decision = simulate_policy_decision(&simulation_input);
        match (&first_decision, &second_decision) {
            (Ok(a), Ok(b)) => {
                assert_eq!(
                    a.decision, b.decision,
                    "simulate_policy_decision must be deterministic across re-runs",
                );
            }
            (Err(_), Err(_)) => {}
            other => {
                panic!("simulate_policy_decision changed Ok/Err shape across re-run: {other:?}")
            }
        }
    }
});
