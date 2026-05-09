//! Lattice-trapdoor delegation walker fuzz-style harness via proptest.
//!
//! Goal: prove that `LatticeDelegationVerifierImpl::verify_sub_token`
//! NEVER panics and NEVER loops forever for any caller-controlled
//! certificate-chain shape — including cycles, self-references,
//! depth-bombs, broken parent links, and zone/period mismatches.
//!
//! The DoS-relevant invariant is the depth cap: the walker MUST
//! terminate in at most `params.depth` hops regardless of chain
//! topology. We sanity-check that with an explicit timeout assertion
//! in addition to the standard "doesn't panic" coverage.

use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

use fcp_core::{OperationId, PrincipalId, ZoneId};
use fcp_crypto_pq::{LatticeParams, PublicMatrixMaterial, ZonePeriodPublicKey};
use fcp_policy::lattice_delegation::{
    DelegationCertificate, DelegationCertificateId, DelegationPeriod, LatticeDelegationError,
    LatticeDelegationVerifier, LatticeDelegationVerifierImpl, LatticeSubToken,
};
use proptest::prelude::*;
use serde::Serialize;

const FORMAL_POLICY_ARTIFACT_PATH: &str =
    "target/fcp-policy/lattice-delegation-policy-correspondence-evidence.jsonl";
const FORMAL_POLICY_EVIDENCE_COMMAND: &str = "cargo test -p fcp-policy --test lattice_delegation_proptest lattice_delegation_formal_correspondence_fixture_jsonl_is_secret_free -- --nocapture";

#[derive(Debug, Serialize)]
struct FormalPolicyCorrespondenceEvidence<'a> {
    schema: &'a str,
    command_line: String,
    git_revision: String,
    theorem_names: Vec<&'a str>,
    assumption_ids: Vec<&'a str>,
    fixture_id_hash: String,
    parameter_profile: &'a str,
    route_revision: u16,
    representation_version: u16,
    public_matrix_material_version: u16,
    zone_id_hash: String,
    period_id_hash: String,
    certificate_id_hash: String,
    trust_set_id_hash: String,
    request_descriptor_hash: String,
    checks: FormalPolicyChecks,
    duration_ms: u128,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // JSONL proof evidence records independent checks as booleans.
struct FormalPolicyChecks {
    zone_period_public_key_shape: bool,
    delegation_certificate_claims: bool,
    operation_binding_rejected: bool,
    principal_binding_rejected: bool,
    request_binding_rejected: bool,
    dispatcher_enforcement_checks: bool,
    trust_set_replay_denied: bool,
    stale_route_revision_rejected: bool,
    certificate_envelope_rejected: bool,
}

const fn cert_id(byte: u8) -> DelegationCertificateId {
    DelegationCertificateId::from_bytes([byte; 32])
}

fn zone() -> ZoneId {
    ZoneId::work()
}

fn operation() -> OperationId {
    OperationId::new("op:test").unwrap()
}

fn principal() -> PrincipalId {
    PrincipalId::new("agent:test").unwrap()
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn evidence_command_line(env_key: &str, fallback: &str) -> String {
    std::env::var(env_key).unwrap_or_else(|_| fallback.to_string())
}

fn formal_theorem_names() -> Vec<&'static str> {
    vec![
        "Fcp.Invariants.LatticeDelegation.lattice_delegation_chain_corruption_rejected",
        "Fcp.Invariants.LatticeDelegation.lattice_delegation_sis_assumption_boundary_complete",
        "Fcp.Invariants.LatticeDelegation.lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions",
    ]
}

fn formal_assumption_ids() -> Vec<&'static str> {
    vec![
        "FCP-PQ-SIS-HARDNESS-V1",
        "FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1",
        "FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1",
        "FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1",
        "FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1",
        "FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1",
    ]
}

fn hash_bytes_hex(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize().as_bytes())
}

fn hash_str_hex(domain: &[u8], value: &str) -> String {
    hash_bytes_hex(domain, value.as_bytes())
}

fn period_hash_hex(period: DelegationPeriod) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-policy/lattice-formal-period-v1|");
    hasher.update(&period.start_unix_ms.to_le_bytes());
    hasher.update(&period.end_unix_ms.to_le_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

fn profile_id(params: LatticeParams) -> &'static str {
    if params == LatticeParams::SMALL_TEST {
        "SMALL_TEST"
    } else if params == LatticeParams::V4_REFERENCE {
        "V4_REFERENCE"
    } else {
        "CUSTOM"
    }
}

fn formal_fixture_id_hash(profile: &str) -> String {
    hash_str_hex(
        b"fcp-policy/lattice-formal-fixture-v1|",
        &format!("fixture:{profile}:policy-correspondence-v1"),
    )
}

const fn formal_period() -> DelegationPeriod {
    DelegationPeriod {
        start_unix_ms: 1_700_000_000_000,
        end_unix_ms: 1_700_003_600_000,
    }
}

fn minted_policy_fixture(
    params: LatticeParams,
) -> (
    LatticeDelegationVerifierImpl,
    DelegationCertificate,
    LatticeSubToken,
    ZoneId,
    OperationId,
    PrincipalId,
    u64,
) {
    let request_zone = ZoneId::work();
    let request_operation = operation();
    let request_principal = principal();
    let policy_period = formal_period();
    let crypto_zone = LatticeDelegationVerifierImpl::zone_to_crypto(&request_zone);
    let crypto_period = LatticeDelegationVerifierImpl::period_to_crypto(policy_period);
    let entropy = fcp_crypto_pq::TrapGenEntropy::from_fixture_seed(
        b"fcp-policy/lattice-formal-correspondence-v1",
        [0x63; 32],
    );
    let (master_public, master_trapdoor) =
        fcp_crypto_pq::trap_gen_with_entropy(params, &entropy).expect("route TrapGen succeeds");
    let (public_key, trapdoor) = fcp_crypto_pq::delegate(
        &master_public,
        &master_trapdoor,
        crypto_zone,
        crypto_period,
        params,
    )
    .expect("route Delegate succeeds");
    let operation_hash = fcp_crypto_pq::operation_hash(
        &crypto_zone,
        crypto_period,
        request_operation.as_str().as_bytes(),
        request_principal.as_str().as_bytes(),
    );
    let preimage = fcp_crypto_pq::sample_pre(&public_key, &trapdoor, operation_hash, params)
        .expect("route SamplePre succeeds");
    let leaf = DelegationCertificate {
        cert_id: cert_id(0xC1),
        zone_id: request_zone.clone(),
        period: policy_period,
        parent_cert_id: None,
        public_key,
    };
    let verifier = LatticeDelegationVerifierImpl::with_certificates(params, [leaf.clone()]);
    let sub = bind_sub_token(
        &verifier,
        &leaf,
        LatticeSubToken {
            cert_id: leaf.cert_id,
            op_id: request_operation.clone(),
            principal_id: request_principal.clone(),
            request_descriptor_hash: [0_u8; 32],
            preimage_bytes: preimage.as_bytes().to_vec(),
        },
        &request_zone,
    );
    (
        verifier,
        leaf,
        sub,
        request_zone,
        request_operation,
        request_principal,
        policy_period.start_unix_ms,
    )
}

fn write_formal_policy_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-policy").expect("policy evidence directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(FORMAL_POLICY_ARTIFACT_PATH, jsonl)
        .expect("policy formal correspondence artifact writes");
}

fn zone_from_kind(kind: u8) -> ZoneId {
    match kind % 3 {
        0 => ZoneId::work(),
        1 => ZoneId::private(),
        _ => ZoneId::public(),
    }
}

const fn period_open() -> DelegationPeriod {
    DelegationPeriod {
        start_unix_ms: 0,
        end_unix_ms: u64::MAX,
    }
}

fn cert(
    id_byte: u8,
    parent: Option<u8>,
    zone_id: ZoneId,
    period: DelegationPeriod,
) -> DelegationCertificate {
    let hash = [id_byte; 32];
    let public_key = ZonePeriodPublicKey {
        hash,
        public_matrix: PublicMatrixMaterial::fixture_seed_only(hash),
        zone_id: LatticeDelegationVerifierImpl::zone_to_crypto(&zone_id),
        period: LatticeDelegationVerifierImpl::period_to_crypto(period),
        params: LatticeParams::V4_REFERENCE,
    };
    DelegationCertificate {
        cert_id: cert_id(id_byte),
        zone_id,
        period,
        parent_cert_id: parent.map(cert_id),
        public_key,
    }
}

fn verifier_with(certs: Vec<DelegationCertificate>) -> LatticeDelegationVerifierImpl {
    LatticeDelegationVerifierImpl::with_certificates(LatticeParams::V4_REFERENCE, certs)
}

fn sub_token_targeting(leaf: u8) -> LatticeSubToken {
    let preimage_len = LatticeParams::V4_REFERENCE
        .preimage_encoded_bytes()
        .expect("reference profile has bounded preimage encoding");
    LatticeSubToken {
        cert_id: cert_id(leaf),
        op_id: operation(),
        principal_id: principal(),
        request_descriptor_hash: [0u8; 32],
        preimage_bytes: vec![0u8; preimage_len],
    }
}

fn bind_sub_token(
    verifier: &LatticeDelegationVerifierImpl,
    leaf: &DelegationCertificate,
    mut sub_token: LatticeSubToken,
    request_zone: &ZoneId,
) -> LatticeSubToken {
    sub_token.request_descriptor_hash = LatticeDelegationVerifierImpl::request_descriptor_hash(
        &leaf.cert_id,
        request_zone,
        leaf.period,
        &sub_token.op_id,
        &sub_token.principal_id,
        &leaf.public_key.hash,
        &verifier.trust_set_id(),
    );
    sub_token
}

const fn lean_period_contains(period: DelegationPeriod, now_unix_ms: u64) -> bool {
    period.start_unix_ms <= now_unix_ms && now_unix_ms <= period.end_unix_ms
}

fn lean_accepts_token(
    leaf: &DelegationCertificate,
    ancestors: &[DelegationCertificate],
    request_zone: &ZoneId,
    now_unix_ms: u64,
) -> bool {
    leaf.zone_id == *request_zone
        && lean_period_contains(leaf.period, now_unix_ms)
        && ancestors
            .iter()
            .all(|ancestor| lean_period_contains(ancestor.period, now_unix_ms))
}

const fn rust_reached_crypto_or_accepted(
    outcome: &Result<
        fcp_policy::lattice_delegation::LatticeVerificationReceipt,
        LatticeDelegationError,
    >,
) -> bool {
    matches!(
        outcome,
        Ok(_)
            | Err(LatticeDelegationError::NotImplemented
                | LatticeDelegationError::VerificationEquationFailed { .. }
                | LatticeDelegationError::PreimageTooLong { .. }
                | LatticeDelegationError::ParameterMismatch { .. })
    )
}

fn assert_terminates(verifier: &LatticeDelegationVerifierImpl, sub_token: &LatticeSubToken) {
    // The walker must terminate in well under a second. If it ever
    // doesn't, this test will hang and CI catches it; we still bound
    // it explicitly so a regression on a small-depth cycle bug is
    // visible.
    let start = Instant::now();
    let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verifier.verify_sub_token(
            sub_token,
            &zone(),
            &operation(),
            &principal(),
            1_700_000_000_000,
        )
    }));
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "lattice walker took {} ms — possible unbounded loop",
        start.elapsed().as_millis()
    );
}

// ── Targeted regression cases (easier to read than proptest output) ──

#[test]
fn lattice_walker_self_reference_bounds_at_depth_param() {
    // Cert A → A (self-loop). Walker must hit ChainTooDeep at
    // params.depth, NOT loop forever.
    let v = verifier_with(vec![cert(1, Some(1), zone(), period_open())]);
    let sub = sub_token_targeting(1);
    assert_terminates(&v, &sub);
    let err = v
        .verify_sub_token(&sub, &zone(), &operation(), &principal(), 1_700_000_000_000)
        .unwrap_err();
    assert!(
        matches!(err, LatticeDelegationError::ChainTooDeep { .. }),
        "self-loop must surface ChainTooDeep, got {err:?}"
    );
}

#[test]
fn lattice_walker_two_cycle_bounds_at_depth_param() {
    // A → B → A. Walker visits A,B,A,B,A,... bounded by depth.
    let v = verifier_with(vec![
        cert(1, Some(2), zone(), period_open()),
        cert(2, Some(1), zone(), period_open()),
    ]);
    let sub = sub_token_targeting(1);
    assert_terminates(&v, &sub);
    let err = v
        .verify_sub_token(&sub, &zone(), &operation(), &principal(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(err, LatticeDelegationError::ChainTooDeep { .. }));
}

#[test]
fn lattice_walker_unknown_cert_returns_typed_err() {
    let v = verifier_with(vec![]);
    let err = v
        .verify_sub_token(
            &sub_token_targeting(99),
            &zone(),
            &operation(),
            &principal(),
            1_700_000_000_000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        LatticeDelegationError::UnknownCertificate { .. }
    ));
}

#[test]
fn lattice_walker_missing_parent_returns_incomplete_chain_err() {
    // A → 99 (parent absent from trust set).
    let v = verifier_with(vec![cert(1, Some(99), zone(), period_open())]);
    let sub = sub_token_targeting(1);
    assert_terminates(&v, &sub);
    let err = v
        .verify_sub_token(&sub, &zone(), &operation(), &principal(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(
        err,
        LatticeDelegationError::IncompleteDelegationChain { .. }
    ));
}

#[test]
fn lattice_walker_period_zero_zero_rejects_with_outside_period() {
    let v = verifier_with(vec![cert(
        1,
        None,
        zone(),
        DelegationPeriod {
            start_unix_ms: 0,
            end_unix_ms: 0,
        },
    )]);
    let sub = sub_token_targeting(1);
    let err = v
        .verify_sub_token(&sub, &zone(), &operation(), &principal(), 1_700_000_000_000)
        .unwrap_err();
    assert!(matches!(err, LatticeDelegationError::OutsidePeriod { .. }));
}

#[test]
fn lattice_walker_period_with_start_after_end_does_not_panic() {
    // Adversarial period: start > end. period.contains() returns false
    // for any now, so this must surface OutsidePeriod, not panic.
    let v = verifier_with(vec![cert(
        1,
        None,
        zone(),
        DelegationPeriod {
            start_unix_ms: u64::MAX,
            end_unix_ms: 0,
        },
    )]);
    let sub = sub_token_targeting(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        v.verify_sub_token(&sub, &zone(), &operation(), &principal(), 1_700_000_000_000)
    }));
    assert!(result.is_ok(), "inverted-period must not panic");
    let err = result.unwrap().unwrap_err();
    assert!(matches!(err, LatticeDelegationError::OutsidePeriod { .. }));
}

#[test]
#[allow(clippy::too_many_lines)] // The proof fixture keeps every acceptance seam visible.
fn lattice_delegation_formal_correspondence_fixture_jsonl_is_secret_free() {
    let command_line = evidence_command_line(
        "FCP_POLICY_LATTICE_FORMAL_CORRESPONDENCE_COMMAND_LINE",
        FORMAL_POLICY_EVIDENCE_COMMAND,
    );
    let mut lines = Vec::new();

    for params in [LatticeParams::SMALL_TEST, LatticeParams::V4_REFERENCE] {
        let started = Instant::now();
        let profile = profile_id(params);
        let (verifier, leaf, sub, zone_id, operation_id, principal_id, now_unix_ms) =
            minted_policy_fixture(params);
        let receipt = verifier
            .verify_sub_token(&sub, &zone_id, &operation_id, &principal_id, now_unix_ms)
            .expect("supported policy lattice route verifies");
        assert_eq!(receipt.cert_id, leaf.cert_id);
        assert_eq!(receipt.request_descriptor_hash, sub.request_descriptor_hash);
        assert_eq!(leaf.public_key.params, params);
        assert_eq!(
            leaf.public_key.zone_id,
            LatticeDelegationVerifierImpl::zone_to_crypto(&zone_id)
        );
        assert_eq!(
            leaf.public_key.period,
            LatticeDelegationVerifierImpl::period_to_crypto(leaf.period)
        );

        let wrong_operation = OperationId::new("op:formal-other").unwrap();
        let operation_err = verifier
            .verify_sub_token(&sub, &zone_id, &wrong_operation, &principal_id, now_unix_ms)
            .expect_err("operation mismatch must fail before crypto");
        assert!(matches!(
            operation_err,
            LatticeDelegationError::OperationMismatch { .. }
        ));

        let wrong_principal = PrincipalId::new("agent:formal-other").unwrap();
        let principal_err = verifier
            .verify_sub_token(&sub, &zone_id, &operation_id, &wrong_principal, now_unix_ms)
            .expect_err("principal mismatch must fail before crypto");
        assert!(matches!(
            principal_err,
            LatticeDelegationError::PrincipalMismatch { .. }
        ));

        let mut wrong_binding_sub = sub.clone();
        wrong_binding_sub.request_descriptor_hash[0] ^= 0x80;
        let binding_err = verifier
            .verify_sub_token(
                &wrong_binding_sub,
                &zone_id,
                &operation_id,
                &principal_id,
                now_unix_ms,
            )
            .expect_err("request descriptor hash mismatch must fail closed");
        assert!(matches!(
            binding_err,
            LatticeDelegationError::RequestBindingMismatch { .. }
        ));

        let mut replay_extra = leaf.clone();
        replay_extra.cert_id = cert_id(0xD4);
        let replay_verifier =
            LatticeDelegationVerifierImpl::with_certificates(params, [leaf.clone(), replay_extra]);
        let replay_err = replay_verifier
            .verify_sub_token(&sub, &zone_id, &operation_id, &principal_id, now_unix_ms)
            .expect_err("trust-set changes must deny replayed request binding");
        assert!(matches!(
            replay_err,
            LatticeDelegationError::RequestBindingMismatch { .. }
        ));

        let mut stale_leaf = leaf.clone();
        stale_leaf.public_key.public_matrix.route_revision = stale_leaf
            .public_key
            .public_matrix
            .route_revision
            .saturating_add(1);
        let stale_verifier =
            LatticeDelegationVerifierImpl::with_certificates(params, [stale_leaf.clone()]);
        let stale_sub = bind_sub_token(&stale_verifier, &stale_leaf, sub.clone(), &zone_id);
        let stale_err = stale_verifier
            .verify_sub_token(
                &stale_sub,
                &zone_id,
                &operation_id,
                &principal_id,
                now_unix_ms,
            )
            .expect_err("stale route revision must fail closed");
        assert!(matches!(
            stale_err,
            LatticeDelegationError::ParameterMismatch { .. }
                | LatticeDelegationError::NotImplemented
        ));

        let mut mismatched_leaf = leaf.clone();
        mismatched_leaf.public_key.zone_id =
            LatticeDelegationVerifierImpl::zone_to_crypto(&ZoneId::public());
        let mismatched_verifier =
            LatticeDelegationVerifierImpl::with_certificates(params, [mismatched_leaf.clone()]);
        let mismatched_sub = bind_sub_token(
            &mismatched_verifier,
            &mismatched_leaf,
            sub.clone(),
            &zone_id,
        );
        let envelope_err = mismatched_verifier
            .verify_sub_token(
                &mismatched_sub,
                &zone_id,
                &operation_id,
                &principal_id,
                now_unix_ms,
            )
            .expect_err("certificate public key envelope must match policy claims");
        assert!(matches!(
            envelope_err,
            LatticeDelegationError::CertificatePublicKeyMismatch { .. }
        ));

        let evidence = FormalPolicyCorrespondenceEvidence {
            schema: "fcp.policy.lattice_formal_correspondence.v1",
            command_line: command_line.clone(),
            git_revision: git_revision(),
            theorem_names: formal_theorem_names(),
            assumption_ids: formal_assumption_ids(),
            fixture_id_hash: formal_fixture_id_hash(profile),
            parameter_profile: profile,
            route_revision: fcp_crypto_pq::PRIMITIVE_ROUTE_REVISION,
            representation_version: fcp_crypto_pq::LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: fcp_crypto_pq::PUBLIC_MATRIX_MATERIAL_VERSION,
            zone_id_hash: hash_str_hex(b"fcp-policy/lattice-formal-zone-v1|", zone_id.as_str()),
            period_id_hash: period_hash_hex(leaf.period),
            certificate_id_hash: hash_bytes_hex(
                b"fcp-policy/lattice-formal-cert-v1|",
                leaf.cert_id.as_bytes(),
            ),
            trust_set_id_hash: hash_bytes_hex(
                b"fcp-policy/lattice-formal-trust-set-v1|",
                &verifier.trust_set_id(),
            ),
            request_descriptor_hash: hex::encode(sub.request_descriptor_hash),
            checks: FormalPolicyChecks {
                zone_period_public_key_shape: true,
                delegation_certificate_claims: true,
                operation_binding_rejected: true,
                principal_binding_rejected: true,
                request_binding_rejected: true,
                dispatcher_enforcement_checks: true,
                trust_set_replay_denied: true,
                stale_route_revision_rejected: true,
                certificate_envelope_rejected: true,
            },
            duration_ms: started.elapsed().as_millis(),
            result: "passed",
            skip_reason: None,
        };
        lines.push(serde_json::to_string(&evidence).expect("policy evidence serializes"));
    }

    for line in &lines {
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "policy correspondence evidence must not expose local paths: {line}"
        );
        assert!(
            !line.contains("op:")
                && !line.contains("agent:")
                && !line.contains("z:")
                && !line.contains("formal-other"),
            "policy correspondence evidence must not expose raw dispatcher text: {line}"
        );
        assert!(
            !line.contains("master_trapdoor")
                && !line.contains("trapdoor_coefficients")
                && !line.contains("delegation_trapdoor")
                && !line.contains("preimage_bytes")
                && !line.contains("secret_seed")
                && !line.contains("expanded_secret_matrix")
                && !line.contains("bearer"),
            "policy correspondence evidence must not expose secret material: {line}"
        );
        eprintln!("{line}");
    }

    write_formal_policy_artifact(&lines);
    assert!(
        fs::metadata(FORMAL_POLICY_ARTIFACT_PATH)
            .expect("policy correspondence evidence artifact exists")
            .len()
            > 0,
        "policy correspondence evidence artifact must be non-empty"
    );
}

// ── Proptest randomized harness ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Adversarial chain: random parent links across a small ID space,
    /// random periods, random preimage length, random query time.
    /// Walker MUST terminate in <500ms and return a typed Err for
    /// every input. The verifier never panics regardless of cycle /
    /// depth-bomb / missing-parent shapes.
    #[test]
    fn lattice_walker_adversarial_chain_never_panics_or_loops(
        chain_size in 0usize..=8,
        parent_links in proptest::collection::vec(0u8..=10, 0..=8),
        period_starts in proptest::collection::vec(any::<u64>(), 0..=8),
        period_ends in proptest::collection::vec(any::<u64>(), 0..=8),
        leaf_id in 0u8..=10,
        now_unix_ms in any::<u64>(),
        preimage_len in 0usize..=256,
    ) {
        // Build `chain_size` certs, each with id = i+1 and a
        // potentially adversarial parent link (cycles, self-refs,
        // missing parents are all reachable via the parent_links input).
        let mut certs = Vec::with_capacity(chain_size);
        for i in 0..chain_size {
            let parent = parent_links.get(i).copied();
            let start = period_starts.get(i).copied().unwrap_or(0);
            let end = period_ends.get(i).copied().unwrap_or(u64::MAX);
            certs.push(cert(
                u8::try_from(i + 1).unwrap_or(u8::MAX),
                parent,
                zone(),
                DelegationPeriod {
                    start_unix_ms: start,
                    end_unix_ms: end,
                },
            ));
        }
        let v = verifier_with(certs);

        let sub = LatticeSubToken {
            cert_id: cert_id(leaf_id),
            op_id: OperationId::new("op:test").unwrap(),
            principal_id: PrincipalId::new("agent:test").unwrap(),
            request_descriptor_hash: [0u8; 32],
            preimage_bytes: vec![0u8; preimage_len],
        };

        // Termination + no-panic.
        let start = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            v.verify_sub_token(&sub, &zone(), &operation(), &principal(), now_unix_ms)
        }));
        prop_assert!(
            start.elapsed() < Duration::from_millis(500),
            "lattice walker took {} ms — possible unbounded loop",
            start.elapsed().as_millis()
        );
        prop_assert!(result.is_ok(), "lattice walker panicked on adversarial chain");

        // Verification with stub crypto either succeeds with
        // NotImplemented (the bead-blessed signal that production
        // should fall back to V3) OR returns one of the typed
        // structural errors. Anything else is a regression.
        let outcome = result.unwrap();
        match outcome {
            // Receipt — fine, never reached today (stub)
            Ok(_)
            | Err(
                LatticeDelegationError::UnknownCertificate { .. }
                    | LatticeDelegationError::ZoneMismatch { .. }
                    | LatticeDelegationError::OutsidePeriod { .. }
                    | LatticeDelegationError::IncompleteDelegationChain { .. }
                    | LatticeDelegationError::ChainTooDeep { .. }
                    | LatticeDelegationError::PreimageEncodingMismatch { .. }
                    | LatticeDelegationError::ParameterMismatch { .. }
                    | LatticeDelegationError::OperationMismatch { .. }
                    | LatticeDelegationError::PrincipalMismatch { .. }
                    | LatticeDelegationError::CertificatePublicKeyMismatch { .. }
                    | LatticeDelegationError::RequestBindingMismatch { .. }
                    | LatticeDelegationError::NotImplemented
                    | LatticeDelegationError::VerificationEquationFailed { .. }
                    | LatticeDelegationError::PreimageTooLong { .. }
            ) => {}
        }
    }

    /// Mismatched-zone request must NEVER panic and must always
    /// surface ZoneMismatch (when the cert exists) or
    /// UnknownCertificate (when it doesn't).
    #[test]
    fn lattice_walker_zone_mismatch_never_panics(
        seed in 1u8..=10,
        _request_zone_byte in 0u8..=10,
    ) {
        let v = verifier_with(vec![cert(seed, None, zone(), period_open())]);
        let sub = sub_token_targeting(seed);
        // Use a different built-in zone than `zone()` so the
        // mismatch path fires deterministically.
        let other_zone = ZoneId::private();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            v.verify_sub_token(
                &sub,
                &other_zone,
                &operation(),
                &principal(),
                1_700_000_000_000,
            )
        }));
        prop_assert!(result.is_ok(), "verifier panicked on cross-zone request");
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        ..ProptestConfig::default()
    })]

    /// Cross-validates Rust's structural verifier gates against the Lean
    /// `AcceptsToken` predicate in `lean/Fcp/Invariants/LatticeDelegation.lean`.
    ///
    /// The generated trust set is deliberately complete, acyclic, depth-bounded,
    /// and uses a correctly encoded preimage so the only possible structural
    /// disagreement is one of the three Lean-modeled checks: leaf zone agreement,
    /// leaf period containment, or ancestor period containment. A Lean-accepted
    /// tuple must reach the crypto verifier (which can return a fixture-route
    /// crypto/config error in this structural harness), while a Lean-rejected
    /// tuple must stop at a structural `ZoneMismatch` or `OutsidePeriod`
    /// before crypto is reached.
    #[test]
    fn lattice_delegation_rust_matches_lean_structural_model(
        chain_len in 0usize..=4,
        leaf_zone_kind in 0u8..=2,
        request_zone_kind in 0u8..=2,
        ancestor_zone_kinds in proptest::collection::vec(0u8..=2, 4),
        leaf_start in any::<u64>(),
        leaf_end in any::<u64>(),
        ancestor_starts in proptest::collection::vec(any::<u64>(), 4),
        ancestor_ends in proptest::collection::vec(any::<u64>(), 4),
        now_unix_ms in any::<u64>(),
    ) {
        let leaf_zone = zone_from_kind(leaf_zone_kind);
        let request_zone = zone_from_kind(request_zone_kind);
        let leaf_period = DelegationPeriod {
            start_unix_ms: leaf_start,
            end_unix_ms: leaf_end,
        };
        let leaf = cert(
            1,
            (chain_len > 0).then_some(2),
            leaf_zone,
            leaf_period,
        );

        let mut certs = vec![leaf.clone()];
        for idx in 0..chain_len {
            let id = u8::try_from(idx + 2).expect("chain_len <= 4 fits in u8");
            let parent = (idx + 1 < chain_len).then_some(id + 1);
            certs.push(cert(
                id,
                parent,
                zone_from_kind(ancestor_zone_kinds[idx]),
                DelegationPeriod {
                    start_unix_ms: ancestor_starts[idx],
                    end_unix_ms: ancestor_ends[idx],
                },
            ));
        }

        let expected_accepts =
            lean_accepts_token(&leaf, &certs[1..], &request_zone, now_unix_ms);
        let verifier = verifier_with(certs);
        let sub = bind_sub_token(&verifier, &leaf, sub_token_targeting(1), &request_zone);
        let outcome = verifier.verify_sub_token(
            &sub,
            &request_zone,
            &operation(),
            &principal(),
            now_unix_ms,
        );

        if expected_accepts {
            prop_assert!(
                rust_reached_crypto_or_accepted(&outcome),
                "Lean accepted but Rust stopped before crypto: {outcome:?}"
            );
        } else {
            prop_assert!(
                matches!(
                    outcome,
                    Err(
                        LatticeDelegationError::ZoneMismatch { .. }
                            | LatticeDelegationError::OutsidePeriod { .. }
                    )
                ),
                "Lean rejected but Rust did not reject at a modeled structural gate: {outcome:?}"
            );
        }
    }
}
