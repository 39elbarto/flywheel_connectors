use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use fcp_crypto_pq as pq;
use fcp_host::{
    CapabilityVerifyCheck, CheckOutcome, EnforcementConfig, EnforcementContextBuilder,
    EnforcementPipeline, PipelineOutcome,
};
use fcp_policy::{
    DelegationCertificate, DelegationCertificateId, DelegationPeriod, LatticeDelegationVerifier,
    LatticeDelegationVerifierImpl, LatticeSubToken, OperationId, PrincipalId, ZoneId,
};
use serde::Serialize;

const COMMAND_LINE: &str =
    "cargo test -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture";
const RELATIVE_ARTIFACT_PATH: &str = "target/fcp-host/lattice-policy-dispatcher-evidence.jsonl";

#[derive(Debug, Clone)]
struct MintedFixture {
    params: pq::LatticeParams,
    profile: &'static str,
    fixture_id_hash: String,
    verifier: LatticeDelegationVerifierImpl,
    certificate: DelegationCertificate,
    sub_token: LatticeSubToken,
    zone: ZoneId,
    operation: OperationId,
    principal: PrincipalId,
    now_unix_ms: u64,
    primitive_timings: PrimitiveTimings,
    norm_bound_bucket: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct MatrixDimensions {
    n: u32,
    m: u32,
    q_bits: u32,
    depth: u8,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct PrimitiveTimings {
    trap_gen_ms: f64,
    delegate_ms: f64,
    sample_pre_ms: f64,
    policy_verify_ms: f64,
    dispatcher_ms: f64,
    pipeline_capability_verify_ms: f64,
    pipeline_non_check_overhead_ms: f64,
    duplicated_measurement_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct CheckTimingRecord {
    name: String,
    outcome: &'static str,
    elapsed_ms: f64,
}

#[derive(Debug, Serialize)]
struct EvidenceRecord {
    command_line: &'static str,
    git_revision: String,
    build_profile: &'static str,
    cargo_target_dir_hash: String,
    cargo_target_dir_class: &'static str,
    worker_host_class: String,
    timing_sample_count: u32,
    artifact_path: &'static str,
    parameter_profile: &'static str,
    fixture_id_hash: String,
    scenario: &'static str,
    zone_id_hash: String,
    period_id_hash: String,
    cert_id_hash: String,
    trust_set_id_hash: String,
    trust_set_source_hash: String,
    operation_id_hash: String,
    principal_id_hash: String,
    request_binding_result: &'static str,
    matrix_dimensions: MatrixDimensions,
    primitive_timings: PrimitiveTimings,
    pipeline_checks: Vec<CheckTimingRecord>,
    norm_bound_bucket: String,
    verifier_result: String,
    receipt_id_hash: Option<String>,
    dispatcher_decision: &'static str,
    error_mapping: Option<String>,
    benchmark_summary: String,
    cleanup_result: &'static str,
    skip_reason: Option<&'static str>,
}

struct ScenarioRecordInputs {
    scenario: &'static str,
    request_binding_result: &'static str,
    verifier_result: String,
    receipt_id_hash: Option<String>,
    dispatcher_decision: &'static str,
    error_mapping: Option<String>,
    timings: PrimitiveTimings,
    pipeline_checks: Vec<CheckTimingRecord>,
}

struct DispatchResult {
    timings: PrimitiveTimings,
    decision: &'static str,
    error: Option<String>,
    pipeline_checks: Vec<CheckTimingRecord>,
}

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(RELATIVE_ARTIFACT_PATH)
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|output| output.status.success().then_some(output.stdout))
        .and_then(|stdout| String::from_utf8(stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

const fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn cargo_target_dir_evidence() -> (String, &'static str) {
    match std::env::var("CARGO_TARGET_DIR") {
        Ok(value) if !value.is_empty() => {
            let class = if value.starts_with("/tmp/") {
                "tmp_absolute"
            } else if value.starts_with('/') {
                "absolute"
            } else {
                "relative"
            };
            (
                digest_hex(b"fcp-host/e2e/cargo-target-dir-v1|", value.as_bytes()),
                class,
            )
        }
        _ => (
            digest_hex(b"fcp-host/e2e/cargo-target-dir-v1|", b"unset"),
            "unset",
        ),
    }
}

fn worker_host_class() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn digest_hex(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(bytes);
    hex::encode(h.finalize().as_bytes())
}

fn cert_id(byte: u8) -> DelegationCertificateId {
    DelegationCertificateId::from_bytes([byte; 32])
}

const fn policy_period() -> DelegationPeriod {
    DelegationPeriod {
        start_unix_ms: 1_700_000_000_000,
        end_unix_ms: 1_700_003_600_000,
    }
}

fn profile_name(params: pq::LatticeParams) -> &'static str {
    if params == pq::LatticeParams::SMALL_TEST {
        "SMALL_TEST"
    } else if params == pq::LatticeParams::V4_REFERENCE {
        "V4_REFERENCE"
    } else {
        "CUSTOM"
    }
}

fn matrix_dimensions(params: pq::LatticeParams) -> MatrixDimensions {
    MatrixDimensions {
        n: params.n,
        m: params.m,
        q_bits: u64::BITS - (params.q - 1).leading_zeros(),
        depth: params.depth,
    }
}

fn norm_bucket(params: pq::LatticeParams, preimage: &pq::LatticePreimage) -> String {
    match (
        pq::preimage_norm_squared(params, preimage),
        pq::preimage_norm_bound_squared(params),
    ) {
        (Ok(norm), Ok(bound)) if norm <= bound / 4 => "within_quarter_bound".to_owned(),
        (Ok(norm), Ok(bound)) if norm <= bound => "within_bound".to_owned(),
        (Ok(_), Ok(_)) => "exceeds_bound".to_owned(),
        _ => "norm_unavailable".to_owned(),
    }
}

fn period_hash(period: DelegationPeriod) -> String {
    let crypto_period = LatticeDelegationVerifierImpl::period_to_crypto(period);
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&crypto_period.start_secs.to_le_bytes());
    bytes.extend_from_slice(&crypto_period.end_secs.to_le_bytes());
    digest_hex(b"fcp-host/e2e/lattice-period-v1|", &bytes)
}

fn trust_source_hash(verifier: &LatticeDelegationVerifierImpl) -> String {
    digest_hex(
        b"fcp-host/e2e/lattice-trust-source-v1|",
        &verifier.trust_set_id(),
    )
}

fn receipt_hash(
    cert_id: DelegationCertificateId,
    trust_set_id: &[u8; 32],
    request_descriptor_hash: &[u8; 32],
) -> String {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(cert_id.as_bytes());
    bytes.extend_from_slice(trust_set_id);
    bytes.extend_from_slice(request_descriptor_hash);
    digest_hex(b"fcp-host/e2e/lattice-receipt-v1|", &bytes)
}

fn minted_fixture(params: pq::LatticeParams, fixture_label: &'static [u8]) -> MintedFixture {
    let zone = "z:prod".parse::<ZoneId>().unwrap();
    let operation = OperationId::new("send_message").unwrap();
    let principal = PrincipalId::new("agent-alpha").unwrap();
    let period = policy_period();
    let crypto_zone = LatticeDelegationVerifierImpl::zone_to_crypto(&zone);
    let crypto_period = LatticeDelegationVerifierImpl::period_to_crypto(period);
    let entropy = pq::TrapGenEntropy::from_fixture_seed(fixture_label, [0xC4; 32]);

    let start = Instant::now();
    let (master_public, master_trapdoor) = pq::trap_gen_with_entropy(params, &entropy).unwrap();
    let trap_gen_ms = start.elapsed().as_secs_f64() * 1000.0;

    let start = Instant::now();
    let (public_key, trapdoor) = pq::delegate(
        &master_public,
        &master_trapdoor,
        crypto_zone,
        crypto_period,
        params,
    )
    .unwrap();
    let delegate_ms = start.elapsed().as_secs_f64() * 1000.0;

    let h = pq::operation_hash(
        &crypto_zone,
        crypto_period,
        operation.as_str().as_bytes(),
        principal.as_str().as_bytes(),
    );
    let start = Instant::now();
    let preimage = pq::sample_pre(&public_key, &trapdoor, h, params).unwrap();
    let sample_pre_ms = start.elapsed().as_secs_f64() * 1000.0;
    let norm_bound_bucket = norm_bucket(params, &preimage);

    let certificate = DelegationCertificate {
        cert_id: cert_id(0xE1),
        zone_id: zone.clone(),
        period,
        parent_cert_id: None,
        public_key,
    };
    let verifier = LatticeDelegationVerifierImpl::with_certificates(params, [certificate.clone()]);
    let request_descriptor_hash = LatticeDelegationVerifierImpl::request_descriptor_hash(
        &certificate.cert_id,
        &zone,
        certificate.period,
        &operation,
        &principal,
        &certificate.public_key.hash,
        &verifier.trust_set_id(),
    );
    let sub_token = LatticeSubToken {
        cert_id: certificate.cert_id,
        op_id: operation.clone(),
        principal_id: principal.clone(),
        request_descriptor_hash,
        preimage_bytes: preimage.as_bytes().to_vec(),
    };

    MintedFixture {
        params,
        profile: profile_name(params),
        fixture_id_hash: digest_hex(b"fcp-host/e2e/lattice-fixture-v1|", fixture_label),
        verifier,
        certificate,
        sub_token,
        zone,
        operation,
        principal,
        now_unix_ms: period.start_unix_ms,
        primitive_timings: PrimitiveTimings {
            trap_gen_ms,
            delegate_ms,
            sample_pre_ms,
            ..PrimitiveTimings::default()
        },
        norm_bound_bucket,
    }
}

fn context_for(
    fixture: &MintedFixture,
    sub_token: LatticeSubToken,
) -> fcp_host::EnforcementContext {
    EnforcementContextBuilder::new()
        .request_id("lattice-e2e-request")
        .connector_id("slack:utility:1.0.0")
        .operation(fixture.operation.as_str())
        .zone_id(fixture.zone.as_str())
        .principal(fixture.principal.as_str())
        .timestamp_ms(fixture.now_unix_ms)
        .capability_claims(vec!["*".to_owned(), "messages.write".to_owned()])
        .required_capability("messages.write")
        .lattice_sub_token(sub_token)
        .build()
        .expect("context has all required fields")
}

fn dispatch(
    verifier: LatticeDelegationVerifierImpl,
    ctx: &fcp_host::EnforcementContext,
) -> DispatchResult {
    let config = EnforcementConfig::new().with_lattice_delegation_verifier(Arc::new(verifier));
    let pipeline =
        EnforcementPipeline::with_checks_and_config(vec![Box::new(CapabilityVerifyCheck)], config);
    let decision = pipeline.evaluate(ctx);
    let pipeline_checks = decision
        .checks_run
        .iter()
        .map(|record| CheckTimingRecord {
            name: record.name.clone(),
            outcome: match &record.outcome {
                CheckOutcome::Allow => "allow",
                CheckOutcome::Deny { .. } => "deny",
                CheckOutcome::Skip { .. } => "skip",
            },
            elapsed_ms: record.elapsed_ms,
        })
        .collect();
    let (dispatcher_decision, dispatcher_error) = match &decision.outcome {
        PipelineOutcome::Allow => ("allow", None),
        PipelineOutcome::Deny { reason_code, .. } => ("deny", Some(reason_code.clone())),
    };

    DispatchResult {
        timings: PrimitiveTimings {
            dispatcher_ms: decision.elapsed_ms,
            pipeline_capability_verify_ms: decision
                .check_elapsed_ms("capability_verify")
                .unwrap_or_default(),
            pipeline_non_check_overhead_ms: decision.non_check_overhead_ms(),
            ..PrimitiveTimings::default()
        },
        decision: dispatcher_decision,
        error: dispatcher_error,
        pipeline_checks,
    }
}

fn timing_summary(primitive_timings: PrimitiveTimings) -> String {
    format!(
        "trap_gen_ms={:.3};delegate_ms={:.3};sample_pre_ms={:.3};standalone_policy_verify_ms={:.3};pipeline_total_ms={:.3};pipeline_capability_verify_ms={:.3};pipeline_non_check_overhead_ms={:.3};duplicated_measurement_ms={:.3}",
        primitive_timings.trap_gen_ms,
        primitive_timings.delegate_ms,
        primitive_timings.sample_pre_ms,
        primitive_timings.policy_verify_ms,
        primitive_timings.dispatcher_ms,
        primitive_timings.pipeline_capability_verify_ms,
        primitive_timings.pipeline_non_check_overhead_ms,
        primitive_timings.duplicated_measurement_ms
    )
}

fn record_for(
    git_revision: &str,
    fixture: &MintedFixture,
    inputs: ScenarioRecordInputs,
) -> EvidenceRecord {
    let mut primitive_timings = fixture.primitive_timings;
    primitive_timings.policy_verify_ms = inputs.timings.policy_verify_ms;
    primitive_timings.dispatcher_ms = inputs.timings.dispatcher_ms;
    primitive_timings.pipeline_capability_verify_ms = inputs.timings.pipeline_capability_verify_ms;
    primitive_timings.pipeline_non_check_overhead_ms =
        inputs.timings.pipeline_non_check_overhead_ms;
    primitive_timings.duplicated_measurement_ms =
        primitive_timings.policy_verify_ms + primitive_timings.dispatcher_ms;
    let (cargo_target_dir_hash, cargo_target_dir_class) = cargo_target_dir_evidence();
    EvidenceRecord {
        command_line: COMMAND_LINE,
        git_revision: git_revision.to_owned(),
        build_profile: build_profile(),
        cargo_target_dir_hash,
        cargo_target_dir_class,
        worker_host_class: worker_host_class(),
        timing_sample_count: 1,
        artifact_path: RELATIVE_ARTIFACT_PATH,
        parameter_profile: fixture.profile,
        fixture_id_hash: fixture.fixture_id_hash.clone(),
        scenario: inputs.scenario,
        zone_id_hash: digest_hex(
            b"fcp-host/e2e/lattice-zone-v1|",
            fixture.zone.as_str().as_bytes(),
        ),
        period_id_hash: period_hash(fixture.certificate.period),
        cert_id_hash: digest_hex(
            b"fcp-host/e2e/lattice-cert-v1|",
            fixture.certificate.cert_id.as_bytes(),
        ),
        trust_set_id_hash: digest_hex(
            b"fcp-host/e2e/lattice-trust-set-v1|",
            &fixture.verifier.trust_set_id(),
        ),
        trust_set_source_hash: trust_source_hash(&fixture.verifier),
        operation_id_hash: digest_hex(
            b"fcp-host/e2e/lattice-operation-v1|",
            fixture.operation.as_str().as_bytes(),
        ),
        principal_id_hash: digest_hex(
            b"fcp-host/e2e/lattice-principal-v1|",
            fixture.principal.as_str().as_bytes(),
        ),
        request_binding_result: inputs.request_binding_result,
        matrix_dimensions: matrix_dimensions(fixture.params),
        primitive_timings,
        pipeline_checks: inputs.pipeline_checks,
        norm_bound_bucket: fixture.norm_bound_bucket.clone(),
        verifier_result: inputs.verifier_result,
        receipt_id_hash: inputs.receipt_id_hash,
        dispatcher_decision: inputs.dispatcher_decision,
        error_mapping: inputs.error_mapping,
        benchmark_summary: timing_summary(primitive_timings),
        cleanup_result: "artifact_flushed",
        skip_reason: None,
    }
}

fn run_scenario(
    git_revision: &str,
    fixture: &MintedFixture,
    scenario: &'static str,
    request_binding_result: &'static str,
    verifier: LatticeDelegationVerifierImpl,
    ctx: fcp_host::EnforcementContext,
) -> EvidenceRecord {
    let sub_token = ctx
        .lattice_sub_token
        .as_ref()
        .expect("scenario context must carry lattice sub-token");
    let request_zone = ctx.zone_id.parse::<ZoneId>().unwrap();
    let request_operation = OperationId::new(ctx.operation.clone()).unwrap();
    let request_principal = PrincipalId::new(ctx.principal.clone()).unwrap();
    let start = Instant::now();
    let verifier_outcome = verifier.verify_sub_token(
        sub_token,
        &request_zone,
        &request_operation,
        &request_principal,
        ctx.timestamp_ms,
    );
    let policy_verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    let (receipt_id_hash, verifier_result, expected_error) = match verifier_outcome {
        Ok(receipt) => (
            Some(receipt_hash(
                receipt.cert_id,
                &receipt.trust_set_id,
                &receipt.request_descriptor_hash,
            )),
            "ok".to_owned(),
            None,
        ),
        Err(error) => {
            let code = match &error {
                fcp_policy::LatticeDelegationError::NotImplemented => "LATTICE_NOT_IMPLEMENTED",
                fcp_policy::LatticeDelegationError::UnknownCertificate { .. } => {
                    "LATTICE_UNKNOWN_CERTIFICATE"
                }
                fcp_policy::LatticeDelegationError::OutsidePeriod { .. } => {
                    "LATTICE_OUTSIDE_PERIOD"
                }
                fcp_policy::LatticeDelegationError::VerificationEquationFailed { .. } => {
                    "LATTICE_VERIFICATION_EQUATION_FAILED"
                }
                fcp_policy::LatticeDelegationError::PreimageTooLong { .. } => {
                    "LATTICE_PREIMAGE_TOO_LONG"
                }
                fcp_policy::LatticeDelegationError::ZoneMismatch { .. } => "LATTICE_ZONE_MISMATCH",
                fcp_policy::LatticeDelegationError::IncompleteDelegationChain { .. } => {
                    "LATTICE_INCOMPLETE_DELEGATION_CHAIN"
                }
                fcp_policy::LatticeDelegationError::ChainTooDeep { .. } => "LATTICE_CHAIN_TOO_DEEP",
                fcp_policy::LatticeDelegationError::PreimageEncodingMismatch { .. } => {
                    "LATTICE_PREIMAGE_ENCODING_MISMATCH"
                }
                fcp_policy::LatticeDelegationError::ParameterMismatch { .. } => {
                    "LATTICE_PARAMETER_MISMATCH"
                }
                fcp_policy::LatticeDelegationError::OperationMismatch { .. } => {
                    "LATTICE_OPERATION_MISMATCH"
                }
                fcp_policy::LatticeDelegationError::PrincipalMismatch { .. } => {
                    "LATTICE_PRINCIPAL_MISMATCH"
                }
                fcp_policy::LatticeDelegationError::CertificatePublicKeyMismatch { .. } => {
                    "LATTICE_CERTIFICATE_PUBLIC_KEY_MISMATCH"
                }
                fcp_policy::LatticeDelegationError::RequestBindingMismatch { .. } => {
                    "LATTICE_REQUEST_BINDING_MISMATCH"
                }
            };
            (None, code.to_owned(), Some(code.to_owned()))
        }
    };

    let dispatch_result = dispatch(verifier, &ctx);
    if let Some(expected_error) = expected_error.as_deref() {
        assert_eq!(dispatch_result.error.as_deref(), Some(expected_error));
    } else {
        assert_eq!(dispatch_result.decision, "allow");
        assert!(dispatch_result.error.is_none());
    }

    record_for(
        git_revision,
        fixture,
        ScenarioRecordInputs {
            scenario,
            request_binding_result,
            verifier_result,
            receipt_id_hash,
            dispatcher_decision: dispatch_result.decision,
            error_mapping: dispatch_result.error,
            timings: PrimitiveTimings {
                policy_verify_ms,
                dispatcher_ms: dispatch_result.timings.dispatcher_ms,
                pipeline_capability_verify_ms: dispatch_result
                    .timings
                    .pipeline_capability_verify_ms,
                pipeline_non_check_overhead_ms: dispatch_result
                    .timings
                    .pipeline_non_check_overhead_ms,
                ..PrimitiveTimings::default()
            },
            pipeline_checks: dispatch_result.pipeline_checks,
        },
    )
}

#[test]
fn lattice_policy_dispatcher_e2e_writes_redaction_safe_jsonl() {
    let git_revision = git_revision();
    let small = minted_fixture(
        pq::LatticeParams::SMALL_TEST,
        b"fcp-host/e2e/lattice-dispatcher-small-v1",
    );
    let v4 = minted_fixture(
        pq::LatticeParams::V4_REFERENCE,
        b"fcp-host/e2e/lattice-dispatcher-v4-reference-v1",
    );

    let mut records = Vec::new();
    for fixture in [&small, &v4] {
        records.push(run_scenario(
            &git_revision,
            fixture,
            if fixture.params == pq::LatticeParams::SMALL_TEST {
                "allow_small_test"
            } else {
                "allow_v4_reference"
            },
            "match",
            fixture.verifier.clone(),
            context_for(fixture, fixture.sub_token.clone()),
        ));
    }

    let mut forged = small.sub_token.clone();
    *forged
        .preimage_bytes
        .first_mut()
        .expect("fixture preimage must not be empty") ^= 0x01;
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_forged_preimage",
        "match",
        small.verifier.clone(),
        context_for(&small, forged),
    ));

    let mut forged_v4 = v4.sub_token.clone();
    *forged_v4
        .preimage_bytes
        .first_mut()
        .expect("fixture preimage must not be empty") ^= 0x01;
    records.push(run_scenario(
        &git_revision,
        &v4,
        "deny_forged_v4_reference",
        "match",
        v4.verifier.clone(),
        context_for(&v4, forged_v4),
    ));

    let mut wrong_zone_ctx = context_for(&small, small.sub_token.clone());
    wrong_zone_ctx.zone_id = "z:public".to_owned();
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_mismatched_zone",
        "not_reached",
        small.verifier.clone(),
        wrong_zone_ctx,
    ));

    let mut wrong_period_ctx = context_for(&small, small.sub_token.clone());
    wrong_period_ctx.timestamp_ms = small.certificate.period.end_unix_ms + 1_000;
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_mismatched_period",
        "not_reached",
        small.verifier.clone(),
        wrong_period_ctx,
    ));

    let mut wrong_operation_ctx = context_for(&small, small.sub_token.clone());
    wrong_operation_ctx.operation = "list_channels".to_owned();
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_mismatched_operation",
        "field_mismatch",
        small.verifier.clone(),
        wrong_operation_ctx,
    ));

    let mut wrong_principal_ctx = context_for(&small, small.sub_token.clone());
    wrong_principal_ctx.principal = "agent-beta".to_owned();
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_mismatched_principal",
        "field_mismatch",
        small.verifier.clone(),
        wrong_principal_ctx,
    ));

    let mut malformed = small.sub_token.clone();
    malformed.preimage_bytes.truncate(4);
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_malformed_preimage",
        "match",
        small.verifier.clone(),
        context_for(&small, malformed),
    ));

    let missing_cert_verifier = LatticeDelegationVerifierImpl::empty(small.params);
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_missing_certificate",
        "not_reached",
        missing_cert_verifier,
        context_for(&small, small.sub_token.clone()),
    ));

    let mut incomplete_leaf = small.certificate.clone();
    incomplete_leaf.parent_cert_id = Some(cert_id(0xB1));
    let incomplete_verifier =
        LatticeDelegationVerifierImpl::with_certificates(small.params, [incomplete_leaf]);
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_incomplete_delegation_chain",
        "not_reached",
        incomplete_verifier,
        context_for(&small, small.sub_token.clone()),
    ));

    let parent_period = small.certificate.period;
    let parent_one = DelegationCertificate {
        cert_id: cert_id(0xB1),
        zone_id: small.zone.clone(),
        period: parent_period,
        parent_cert_id: None,
        public_key: small.certificate.public_key.clone(),
    };
    let parent_two = DelegationCertificate {
        cert_id: cert_id(0xB2),
        zone_id: small.zone.clone(),
        period: parent_period,
        parent_cert_id: Some(parent_one.cert_id),
        public_key: small.certificate.public_key.clone(),
    };
    let parent_three = DelegationCertificate {
        cert_id: cert_id(0xB3),
        zone_id: small.zone.clone(),
        period: parent_period,
        parent_cert_id: Some(parent_two.cert_id),
        public_key: small.certificate.public_key.clone(),
    };
    let mut chain_leaf = small.certificate.clone();
    chain_leaf.parent_cert_id = Some(parent_three.cert_id);
    let chain_too_deep_verifier = LatticeDelegationVerifierImpl::with_certificates(
        small.params,
        [parent_one, parent_two, parent_three, chain_leaf],
    );
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_chain_too_deep",
        "not_reached",
        chain_too_deep_verifier,
        context_for(&small, small.sub_token.clone()),
    ));

    let mut extra_cert = small.certificate.clone();
    extra_cert.cert_id = cert_id(0xE2);
    let trust_replay_verifier = LatticeDelegationVerifierImpl::with_certificates(
        small.params,
        [small.certificate.clone(), extra_cert],
    );
    records.push(run_scenario(
        &git_revision,
        &small,
        "deny_trust_set_replay",
        "mismatch",
        trust_replay_verifier,
        context_for(&small, small.sub_token.clone()),
    ));

    let mut extra_v4_cert = v4.certificate.clone();
    extra_v4_cert.cert_id = cert_id(0xE3);
    let v4_trust_replay_verifier = LatticeDelegationVerifierImpl::with_certificates(
        v4.params,
        [v4.certificate.clone(), extra_v4_cert],
    );
    records.push(run_scenario(
        &git_revision,
        &v4,
        "deny_trust_set_replay_v4_reference",
        "mismatch",
        v4_trust_replay_verifier,
        context_for(&v4, v4.sub_token.clone()),
    ));

    let path = artifact_path();
    let parent = path.parent().expect("artifact has parent");
    fs::create_dir_all(parent).expect("create artifact directory");
    let file = File::create(&path).expect("create JSONL artifact");
    let mut writer = BufWriter::new(file);
    for record in &records {
        serde_json::to_writer(&mut writer, record).expect("serialize evidence record");
        writer.write_all(b"\n").expect("write JSONL newline");
    }
    writer.flush().expect("flush JSONL artifact");

    let artifact = fs::read_to_string(&path).expect("read JSONL artifact for redaction scan");
    for forbidden in [
        "/Users/",
        "/tmp/",
        "send_message",
        "agent-alpha",
        "agent-beta",
        "z:prod",
        "z:public",
        "preimage_bytes",
        "trapdoor",
        "token",
        "bearer",
    ] {
        assert!(
            !artifact.contains(forbidden),
            "JSONL artifact leaked forbidden text {forbidden:?}"
        );
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR")
        && !target_dir.is_empty()
    {
        assert!(
            !artifact.contains(&target_dir),
            "JSONL artifact leaked raw CARGO_TARGET_DIR"
        );
    }
    assert!(
        artifact.contains("\"dispatcher_decision\":\"allow\""),
        "artifact records dispatcher allow"
    );
    assert!(
        artifact.contains("\"dispatcher_decision\":\"deny\""),
        "artifact records dispatcher deny"
    );
    assert!(
        artifact.contains("LATTICE_REQUEST_BINDING_MISMATCH"),
        "artifact records request-binding replay denial"
    );
    assert!(
        artifact.contains("\"pipeline_capability_verify_ms\""),
        "artifact records capability_verify check timing"
    );
    assert!(
        artifact.contains("\"pipeline_checks\""),
        "artifact records per-check timing details"
    );
    assert!(
        artifact.contains("\"cargo_target_dir_hash\""),
        "artifact records CARGO_TARGET_DIR fingerprint"
    );
    assert!(
        artifact.contains(
            "\"artifact_path\":\"target/fcp-host/lattice-policy-dispatcher-evidence.jsonl\""
        ),
        "artifact records stable relative artifact path"
    );
    assert!(
        artifact.contains("deny_forged_v4_reference"),
        "artifact covers V4 forged denial in the pipeline"
    );
    assert!(
        artifact.contains("deny_trust_set_replay_v4_reference"),
        "artifact covers V4 replay denial in the pipeline"
    );
    assert_eq!(records.len(), 14);
}

#[test]
fn timing_summary_keeps_duplicate_measurement_visible_but_not_primary() {
    let summary = timing_summary(PrimitiveTimings {
        trap_gen_ms: 1.0,
        delegate_ms: 2.0,
        sample_pre_ms: 3.0,
        policy_verify_ms: 4.0,
        dispatcher_ms: 5.0,
        pipeline_capability_verify_ms: 4.9,
        pipeline_non_check_overhead_ms: 0.1,
        duplicated_measurement_ms: 9.0,
    });

    assert!(summary.contains("standalone_policy_verify_ms=4.000"));
    assert!(summary.contains("pipeline_total_ms=5.000"));
    assert!(summary.contains("pipeline_capability_verify_ms=4.900"));
    assert!(summary.contains("pipeline_non_check_overhead_ms=0.100"));
    assert!(summary.contains("duplicated_measurement_ms=9.000"));
    assert!(!summary.contains("/tmp/"));
}
