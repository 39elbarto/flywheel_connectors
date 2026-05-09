use std::{borrow::Cow, fs, process::Command, time::Instant};

use serde::Serialize;

use fcp_crypto_pq::{
    DelegationPeriod, LATTICE_REPRESENTATION_VERSION, LatticeParams, LatticePqError,
    LatticePreimage, LatticeRepresentationProfile, OperationHash, PRIMITIVE_ROUTE_ID,
    PRIMITIVE_ROUTE_REVISION, PUBLIC_MATRIX_MATERIAL_VERSION, PublicMatrixMaterialKind,
    SecretStorageLengthBucket, TrapGenEntropy, TrapdoorNormQualityBucket, TrapdoorRelationResult,
    delegate, delegate_fixture, expand_operation_hash_rhs, operation_hash,
    preimage_norm_bound_squared, preimage_norm_squared, primitive_route_profile_name,
    reconstruct_public_matrix_coefficient, reconstruct_public_matrix_digest, sample_pre,
    trap_gen_fixture, trap_gen_with_entropy, verify,
};

#[derive(Debug, Serialize)]
struct EvidenceLog<'a> {
    command_line: Cow<'a, str>,
    git_revision: String,
    artifact_path: &'a str,
    fixture_id: &'a str,
    profile: &'a str,
    representation_version: u16,
    params: LatticeParams,
    matrix_dimensions: MatrixDimensions,
    encoded_public_lengths: EncodedPublicLengths,
    encoded_lengths: EncodedLengths,
    allocation_estimate: AllocationEstimate,
    relation_check_result: RelationCheckResultEvidence,
    trapdoor_norm_quality_bucket: TrapdoorNormQualityEvidence,
    secret_storage_len_bucket: SecretStorageBucketEvidence,
    redaction: RedactionEvidence,
    deterministic_shake_compatibility: DeterministicShakeCompatibility,
    policy_bridge_compatibility: PolicyBridgeCompatibility,
    timing_ms: u128,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

const ARTIFACT_PATH: &str = "target/fcp-crypto-pq/representation-profile-evidence.jsonl";
const ROUTE_ARTIFACT_PATH: &str = "target/fcp-crypto-pq/trapgen-delegate-route-evidence.jsonl";
const PUBLIC_MATRIX_ARTIFACT_PATH: &str =
    "target/fcp-crypto-pq/public-matrix-reconstruction-evidence.jsonl";
const SAMPLE_PRE_VERIFY_ARTIFACT_PATH: &str =
    "target/fcp-crypto-pq/sample-pre-verify-evidence.jsonl";
const FORMAL_CORRESPONDENCE_ARTIFACT_PATH: &str =
    "target/fcp-crypto-pq/lattice-delegation-formal-correspondence-evidence.jsonl";
const ROUTE_FIXTURE_ID: &str = "fixture:small_test:trapgen-delegate-route-v1";
const REPRESENTATION_EVIDENCE_COMMAND: &str = "cargo test -p fcp-crypto-pq representation_profile_evidence_jsonl_is_secret_free -- --nocapture";
const ROUTE_EVIDENCE_COMMAND: &str = "cargo test -p fcp-crypto-pq trapgen_delegate_route_evidence_jsonl_is_secret_free -- --nocapture";
const PUBLIC_MATRIX_EVIDENCE_COMMAND: &str = "cargo test -p fcp-crypto-pq public_matrix_reconstruction_evidence_jsonl_is_secret_free -- --nocapture";
const SAMPLE_PRE_VERIFY_EVIDENCE_COMMAND: &str =
    "cargo test -p fcp-crypto-pq sample_pre_verify_evidence_jsonl_is_secret_free -- --nocapture";
const FORMAL_CORRESPONDENCE_EVIDENCE_COMMAND: &str = "cargo test -p fcp-crypto-pq --test representation_profile lean_sis_assumption_boundary_correspondence_fixture_jsonl_is_secret_free -- --nocapture";
const V4_ROUTE_FIXTURE_ID: &str = "fixture:v4_reference:trapgen-delegate-route-v1";

#[derive(Debug, Serialize)]
struct MatrixDimensions {
    n: u32,
    m: u32,
    q: u64,
    coefficient_bytes: usize,
}

#[derive(Debug, Serialize)]
struct EncodedLengths {
    #[serde(rename = "public_matrix_seed_bytes")]
    public_matrix_seed: usize,
    #[serde(rename = "public_matrix_expanded_bytes")]
    public_matrix_expanded: usize,
    #[serde(rename = "trapdoor_storage_bytes")]
    trapdoor_storage: usize,
    #[serde(rename = "preimage_encoded_bytes")]
    preimage_encoded: usize,
}

#[derive(Debug, Serialize)]
struct EncodedPublicLengths {
    #[serde(rename = "master_public_seed_bytes")]
    master_public_seed: usize,
    #[serde(rename = "zone_period_public_seed_bytes")]
    zone_period_public_seed: usize,
    #[serde(rename = "operation_hash_bytes")]
    operation_hash: usize,
}

#[derive(Debug, Serialize)]
struct AllocationEstimate {
    #[serde(rename = "public_matrix_expanded_bytes")]
    public_matrix_expanded: usize,
    #[serde(rename = "max_public_matrix_expanded_bytes")]
    max_public_matrix_expanded: usize,
    #[serde(rename = "preimage_encoded_bytes")]
    preimage_encoded: usize,
    #[serde(rename = "max_preimage_encoded_bytes")]
    max_preimage_encoded: usize,
}

#[derive(Debug, Serialize)]
struct RelationCheckResultEvidence {
    root: TrapdoorRelationResult,
    child: TrapdoorRelationResult,
}

#[derive(Debug, Serialize)]
struct TrapdoorNormQualityEvidence {
    root: TrapdoorNormQualityBucket,
    child: TrapdoorNormQualityBucket,
}

#[derive(Debug, Serialize)]
struct SecretStorageBucketEvidence {
    root: SecretStorageLengthBucket,
    child: SecretStorageLengthBucket,
}

#[derive(Debug, Serialize)]
struct RedactionEvidence {
    master_trapdoor_debug_redacted: bool,
    zone_period_trapdoor_debug_redacted: bool,
    preimage_debug_redacted: bool,
}

#[derive(Debug, Serialize)]
struct DeterministicShakeCompatibility {
    fixture_public_generation_version: u16,
    #[serde(rename = "master_public_seed_blake3_hex")]
    master_public_seed: String,
    #[serde(rename = "zone_period_seed_blake3_hex")]
    zone_period_seed: String,
    #[serde(rename = "operation_hash_hex")]
    operation_hash: String,
}

#[derive(Debug, Serialize)]
struct PolicyBridgeCompatibility {
    preimage_length_matches_profile: bool,
    rejects_legacy_fixed_64_byte_preimage: bool,
}

#[derive(Debug, Serialize)]
struct RouteEvidenceLog<'a> {
    command_line: Cow<'a, str>,
    git_revision: String,
    primitive_route_id: &'a str,
    primitive_route_revision: u16,
    representation_version: u16,
    parameter_profile: &'a str,
    fixture_id: String,
    zone_id_hash: String,
    period_id_hash: String,
    matrix_dimensions: MatrixDimensions,
    root_relation_result: Option<TrapdoorRelationResult>,
    child_relation_result: Option<TrapdoorRelationResult>,
    trapdoor_norm_quality_bucket: RouteTrapdoorNormQualityEvidence,
    allocation_summary: AllocationEstimate,
    primitive_timings_ms: RoutePrimitiveTimings,
    timing_ms: u128,
    cleanup: &'a str,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct RouteTrapdoorNormQualityEvidence {
    root: Option<TrapdoorNormQualityBucket>,
    child: Option<TrapdoorNormQualityBucket>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct RoutePrimitiveTimings {
    trap_gen: u128,
    delegate: u128,
    relation_checks: u128,
}

#[derive(Debug, Serialize)]
struct PublicMatrixEvidenceLog<'a> {
    command_line: Cow<'a, str>,
    git_revision: String,
    primitive_route_id: &'a str,
    primitive_route_revision: u16,
    representation_version: u16,
    public_matrix_material_version: u16,
    parameter_profile: &'a str,
    fixture_id: String,
    zone_id_hash: String,
    period_id_hash: String,
    public_material_summary: PublicMaterialSummary,
    matrix_dimensions: MatrixDimensions,
    child_relation_result: Option<TrapdoorRelationResult>,
    reconstruction_result: &'a str,
    allocation_summary: AllocationEstimate,
    timing_ms: u128,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct PublicMaterialSummary {
    kind: PublicMatrixMaterialKind,
    public_seed_bytes: usize,
    tail_coefficients_bytes: usize,
    binding_hash_hex: String,
    material_digest_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct SamplePreVerifyEvidenceLog<'a> {
    command_line: Cow<'a, str>,
    git_revision: String,
    primitive_route_id: &'a str,
    primitive_route_revision: u16,
    representation_version: u16,
    parameter_profile: &'a str,
    fixture_id: String,
    zone_id_hash: String,
    period_id_hash: String,
    h_fixture_id: String,
    matrix_dimensions: MatrixDimensions,
    norm_bound_squared: u128,
    observed_norm_squared: u128,
    observed_norm_bucket: &'a str,
    primitive_timings_ms: PrimitiveTimings,
    verify_outcome: &'a str,
    error_mapping: Option<&'a str>,
    timeout_cancel_result: &'a str,
    cleanup: &'a str,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct FormalCorrespondenceEvidenceLog<'a> {
    schema: &'a str,
    command_line: Cow<'a, str>,
    git_revision: String,
    theorem_names: Vec<&'a str>,
    assumption_ids: Vec<&'a str>,
    fixture_id_hash: String,
    fixture_category: &'a str,
    parameter_profile: &'a str,
    primitive_route_id: &'a str,
    primitive_route_revision: u16,
    representation_version: u16,
    public_matrix_material_version: u16,
    zone_id_hash: String,
    period_id_hash: String,
    public_material_summary: PublicMaterialSummary,
    matrix_dimensions: MatrixDimensions,
    checks: FormalCryptoCorrespondenceChecks,
    artifact_hashes: FormalArtifactHashes,
    duration_ms: u128,
    result: &'a str,
    skip_reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // JSONL proof evidence records independent checks as booleans.
struct FormalCryptoCorrespondenceChecks {
    public_material_reconstruction: bool,
    route_profile_domain_separation: bool,
    operation_principal_domain_separation: bool,
    malformed_public_header_rejected: bool,
    malformed_tail_coefficients_rejected: bool,
    stale_route_revision_rejected: bool,
    unsupported_profile_rejected: bool,
}

#[derive(Debug, Serialize)]
struct FormalArtifactHashes {
    public_material_digest_hex: Option<String>,
    public_seed_hash_hex: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct PrimitiveTimings {
    trap_gen: u128,
    delegate: u128,
    sample_pre: u128,
    verify: u128,
}

const fn period() -> DelegationPeriod {
    DelegationPeriod {
        start_secs: 1_700_000_000,
        end_secs: 1_700_003_600,
    }
}

const fn verify_result(
    verify_outcome: &Result<(), LatticePqError>,
) -> (&'static str, Option<&'static str>) {
    match verify_outcome {
        Ok(()) => ("passed", None),
        Err(_) => ("failed", None),
    }
}

fn rejects_legacy_fixed_64_byte_preimage(
    params: LatticeParams,
    preimage_encoded_bytes: usize,
) -> bool {
    if preimage_encoded_bytes == 64 {
        return false;
    }

    matches!(
        LatticePreimage::from_encoded_bytes(params, vec![0_u8; 64]),
        Err(LatticePqError::InvalidEncodingLength { .. })
    )
}

fn fixture_id(profile: &str) -> &'static str {
    match profile {
        "SMALL_TEST" => "fixture:small_test:representation-v2",
        "V4_REFERENCE" => "fixture:v4_reference:representation-v2",
        _ => "fixture:unknown:representation-v2",
    }
}

fn hashed_fixture_id_for(fixture_id: &str) -> String {
    format!(
        "hash:{}",
        hex::encode(blake3::hash(fixture_id.as_bytes()).as_bytes())
    )
}

fn hashed_fixture_id() -> String {
    hashed_fixture_id_for(ROUTE_FIXTURE_ID)
}

fn route_fixture_entropy() -> TrapGenEntropy {
    TrapGenEntropy::from_fixture_seed(ROUTE_FIXTURE_ID.as_bytes(), [0x5A; 32])
}

fn v4_route_fixture_entropy() -> TrapGenEntropy {
    TrapGenEntropy::from_fixture_seed(V4_ROUTE_FIXTURE_ID.as_bytes(), [0xA9; 32])
}

fn evidence_command_line<'a>(env_key: &str, default_command: &'a str) -> Cow<'a, str> {
    std::env::var(env_key).map_or(Cow::Borrowed(default_command), Cow::Owned)
}

fn zone_id_hash(zone: &[u8; 32]) -> String {
    hex::encode(blake3::hash(zone).as_bytes())
}

fn period_id_hash(period: DelegationPeriod) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/route-evidence-period-hash-v1|");
    hasher.update(&period.start_secs.to_le_bytes());
    hasher.update(&period.end_secs.to_le_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

const fn matrix_dimensions(
    params: LatticeParams,
    representation: &LatticeRepresentationProfile,
) -> MatrixDimensions {
    MatrixDimensions {
        n: params.n,
        m: params.m,
        q: params.q,
        coefficient_bytes: representation.coefficient_bytes,
    }
}

const fn encoded_lengths(representation: &LatticeRepresentationProfile) -> EncodedLengths {
    EncodedLengths {
        public_matrix_seed: representation.public_matrix_seed_bytes,
        public_matrix_expanded: representation.public_matrix_expanded_bytes,
        trapdoor_storage: representation.trapdoor_storage_bytes,
        preimage_encoded: representation.preimage_encoded_bytes,
    }
}

const fn allocation_estimate(representation: &LatticeRepresentationProfile) -> AllocationEstimate {
    AllocationEstimate {
        public_matrix_expanded: representation.public_matrix_expanded_bytes,
        max_public_matrix_expanded: 64 * 1024 * 1024,
        preimage_encoded: representation.preimage_encoded_bytes,
        max_preimage_encoded: 1024 * 1024,
    }
}

fn redaction_evidence(
    master_debug: &str,
    zone_debug: &str,
    preimage_debug: &str,
) -> RedactionEvidence {
    RedactionEvidence {
        master_trapdoor_debug_redacted: master_debug.contains("<redacted>")
            && !master_debug.contains("bytes"),
        zone_period_trapdoor_debug_redacted: zone_debug.contains("<redacted>")
            && !zone_debug.contains("bytes"),
        preimage_debug_redacted: preimage_debug.contains("<redacted>")
            && !preimage_debug.contains("bytes"),
    }
}

fn deterministic_shake_compatibility(
    master_seed: [u8; 32],
    zone_period_seed: [u8; 32],
    op_hash: OperationHash,
) -> DeterministicShakeCompatibility {
    DeterministicShakeCompatibility {
        fixture_public_generation_version: fcp_crypto_pq::FIXTURE_SHAKE_COMPATIBILITY_VERSION,
        master_public_seed: hex::encode(blake3::hash(&master_seed).as_bytes()),
        zone_period_seed: hex::encode(blake3::hash(&zone_period_seed).as_bytes()),
        operation_hash: hex::encode(op_hash.0),
    }
}

fn policy_bridge_compatibility(
    params: LatticeParams,
    representation: &LatticeRepresentationProfile,
    preimage: &LatticePreimage,
) -> PolicyBridgeCompatibility {
    PolicyBridgeCompatibility {
        preimage_length_matches_profile: preimage.encoded_len()
            == representation.preimage_encoded_bytes,
        rejects_legacy_fixed_64_byte_preimage: rejects_legacy_fixed_64_byte_preimage(
            params,
            representation.preimage_encoded_bytes,
        ),
    }
}

fn evidence_for(profile: &'static str, params: LatticeParams) -> EvidenceLog<'static> {
    let started = Instant::now();
    let representation = params
        .representation_profile()
        .expect("test profiles must have bounded representation");
    let entropy = route_fixture_entropy();
    let (master_pub, master_trap) =
        trap_gen_with_entropy(params, &entropy).expect("route trap_gen succeeds");
    let zone = [0xA5; 32];
    let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, period(), params)
        .expect("route delegate succeeds");
    let op_hash = operation_hash(&zone, period(), b"op:read", b"principal:alice");
    let preimage =
        sample_pre(&zone_pub, &zone_trap, op_hash, params).expect("route SamplePre succeeds");
    let root_relation = master_trap.relation_summary(&master_pub);
    let child_relation = zone_trap.relation_summary(&zone_pub, &master_pub);
    let verify_outcome = verify(&zone_pub, op_hash, &preimage, period().start_secs, params);
    let (result, skip_reason) = verify_result(&verify_outcome);

    let redaction = redaction_evidence(
        &format!("{master_trap:?}"),
        &format!("{zone_trap:?}"),
        &format!("{preimage:?}"),
    );

    EvidenceLog {
        command_line: evidence_command_line(
            "FCP_CRYPTO_PQ_REPRESENTATION_EVIDENCE_COMMAND_LINE",
            REPRESENTATION_EVIDENCE_COMMAND,
        ),
        git_revision: git_revision(),
        artifact_path: ARTIFACT_PATH,
        fixture_id: fixture_id(profile),
        profile,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        params,
        matrix_dimensions: matrix_dimensions(params, &representation),
        encoded_public_lengths: EncodedPublicLengths {
            master_public_seed: master_pub.hash.len(),
            zone_period_public_seed: zone_pub.hash.len(),
            operation_hash: op_hash.0.len(),
        },
        encoded_lengths: encoded_lengths(&representation),
        allocation_estimate: allocation_estimate(&representation),
        relation_check_result: RelationCheckResultEvidence {
            root: root_relation.result,
            child: child_relation.result,
        },
        trapdoor_norm_quality_bucket: TrapdoorNormQualityEvidence {
            root: root_relation.norm_quality_bucket,
            child: child_relation.norm_quality_bucket,
        },
        secret_storage_len_bucket: SecretStorageBucketEvidence {
            root: master_trap.secret_storage_len_bucket(),
            child: zone_trap.secret_storage_len_bucket(),
        },
        redaction,
        deterministic_shake_compatibility: deterministic_shake_compatibility(
            master_pub.hash,
            zone_pub.hash,
            op_hash,
        ),
        policy_bridge_compatibility: policy_bridge_compatibility(
            params,
            &representation,
            &preimage,
        ),
        timing_ms: started.elapsed().as_millis(),
        result,
        skip_reason,
    }
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

fn write_jsonl_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-crypto-pq").expect("evidence artifact directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(ARTIFACT_PATH, jsonl).expect("evidence artifact writes");
}

fn write_route_jsonl_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-crypto-pq").expect("evidence artifact directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(ROUTE_ARTIFACT_PATH, jsonl).expect("route evidence artifact writes");
}

fn write_public_matrix_jsonl_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-crypto-pq").expect("evidence artifact directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(PUBLIC_MATRIX_ARTIFACT_PATH, jsonl).expect("public matrix evidence artifact writes");
}

fn write_sample_pre_verify_jsonl_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-crypto-pq").expect("evidence artifact directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(SAMPLE_PRE_VERIFY_ARTIFACT_PATH, jsonl)
        .expect("SamplePre/Verify evidence artifact writes");
}

fn write_formal_correspondence_jsonl_artifact(lines: &[String]) {
    fs::create_dir_all("target/fcp-crypto-pq").expect("evidence artifact directory is writable");
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    fs::write(FORMAL_CORRESPONDENCE_ARTIFACT_PATH, jsonl)
        .expect("formal correspondence evidence artifact writes");
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

fn formal_correspondence_fixture_id(profile: &str) -> String {
    hashed_fixture_id_for(&format!("fixture:{profile}:formal-correspondence-v1"))
}

#[allow(clippy::too_many_lines)] // The proof-evidence builder keeps one JSONL record's provenance local.
fn formal_correspondence_evidence_for(
    command_line: Cow<'static, str>,
    profile: &'static str,
    params: LatticeParams,
    entropy: &TrapGenEntropy,
) -> FormalCorrespondenceEvidenceLog<'static> {
    let started = Instant::now();
    let representation = params
        .representation_profile()
        .expect("formal correspondence profile representation is bounded");
    let zone = [0xC3; 32];
    let period = period();
    let (master_pub, master_trap) =
        trap_gen_with_entropy(params, entropy).expect("formal TrapGen succeeds");
    let (zone_pub, _zone_trap) = delegate(&master_pub, &master_trap, zone, period, params)
        .expect("formal Delegate succeeds");
    let material_digest = reconstruct_public_matrix_digest(&zone_pub, params)
        .expect("formal public material reconstructs");

    let h_read = operation_hash(&zone, period, b"formal-read", b"formal-principal-a");
    let h_write = operation_hash(&zone, period, b"formal-write", b"formal-principal-a");
    let h_other_principal = operation_hash(&zone, period, b"formal-read", b"formal-principal-b");
    assert_ne!(h_read, h_write, "operation id must domain-separate RHS");
    assert_ne!(
        h_read, h_other_principal,
        "principal id must domain-separate RHS"
    );

    let mut wrong_seed = zone_pub.clone();
    wrong_seed.public_matrix.public_seed[0] ^= 0x44;
    assert_ne!(
        reconstruct_public_matrix_digest(&wrong_seed, params)
            .expect("wrong public seed remains syntactically valid"),
        material_digest,
        "public seed changes must affect public material digest"
    );

    let mut wrong_header = zone_pub.clone();
    wrong_header.public_matrix.version = wrong_header.public_matrix.version.saturating_add(1);
    assert!(matches!(
        reconstruct_public_matrix_digest(&wrong_header, params),
        Err(LatticePqError::InvalidEncodingLength {
            material: "public_matrix_material_version",
            ..
        })
    ));

    let mut wrong_tail = zone_pub.clone();
    let coefficient_bytes = params
        .coefficient_bytes()
        .expect("coefficient byte length is bounded");
    let tail_len = wrong_tail.public_matrix.tail_coefficients.len();
    let last_coeff_offset = tail_len - coefficient_bytes;
    let invalid = params.q.to_le_bytes();
    wrong_tail.public_matrix.tail_coefficients
        [last_coeff_offset..last_coeff_offset + coefficient_bytes]
        .copy_from_slice(&invalid[..coefficient_bytes]);
    assert!(matches!(
        reconstruct_public_matrix_digest(&wrong_tail, params),
        Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_tail",
            ..
        })
    ));

    let mut stale_route = zone_pub.clone();
    stale_route.public_matrix.route_revision += 1;
    assert!(matches!(
        reconstruct_public_matrix_digest(&stale_route, params),
        Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_material",
            ..
        })
    ));

    let mut unsupported = LatticeParams::V4_REFERENCE;
    unsupported.depth = 3;
    let (fixture_master_pub, fixture_master_trap) =
        trap_gen_fixture(unsupported).expect("fixture custom setup succeeds");
    let (fixture_zone_pub, _) = delegate_fixture(
        &fixture_master_pub,
        &fixture_master_trap,
        zone,
        period,
        unsupported,
    )
    .expect("fixture custom delegate succeeds");
    assert!(matches!(
        reconstruct_public_matrix_digest(&fixture_zone_pub, unsupported),
        Err(LatticePqError::UnsupportedPrimitiveRoute { .. })
    ));

    FormalCorrespondenceEvidenceLog {
        schema: "fcp.crypto_pq.lattice_formal_correspondence.v1",
        command_line,
        git_revision: git_revision(),
        theorem_names: formal_theorem_names(),
        assumption_ids: formal_assumption_ids(),
        fixture_id_hash: formal_correspondence_fixture_id(profile),
        fixture_category: "deterministic-public-correspondence",
        parameter_profile: profile,
        primitive_route_id: PRIMITIVE_ROUTE_ID,
        primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
        zone_id_hash: zone_id_hash(&zone),
        period_id_hash: period_id_hash(period),
        public_material_summary: public_material_summary(
            zone_pub.hash,
            zone_pub.public_matrix.kind,
            zone_pub.public_matrix.seed().len(),
            zone_pub.public_matrix.tail_coefficients_len(),
            Some(material_digest),
        ),
        matrix_dimensions: matrix_dimensions(params, &representation),
        checks: FormalCryptoCorrespondenceChecks {
            public_material_reconstruction: true,
            route_profile_domain_separation: true,
            operation_principal_domain_separation: true,
            malformed_public_header_rejected: true,
            malformed_tail_coefficients_rejected: true,
            stale_route_revision_rejected: true,
            unsupported_profile_rejected: true,
        },
        artifact_hashes: FormalArtifactHashes {
            public_material_digest_hex: Some(hex::encode(material_digest)),
            public_seed_hash_hex: hex::encode(
                blake3::hash(&zone_pub.public_matrix.public_seed).as_bytes(),
            ),
        },
        duration_ms: started.elapsed().as_millis(),
        result: "passed",
        skip_reason: None,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // The correspondence fixture is intentionally explicit.
fn lean_sis_assumption_boundary_correspondence_fixture_jsonl_is_secret_free() {
    let command_line = evidence_command_line(
        "FCP_CRYPTO_PQ_FORMAL_CORRESPONDENCE_COMMAND_LINE",
        FORMAL_CORRESPONDENCE_EVIDENCE_COMMAND,
    );
    let mut lines = Vec::new();
    for (profile, params, entropy) in [
        (
            "SMALL_TEST",
            LatticeParams::SMALL_TEST,
            route_fixture_entropy(),
        ),
        (
            "V4_REFERENCE",
            LatticeParams::V4_REFERENCE,
            v4_route_fixture_entropy(),
        ),
    ] {
        let evidence =
            formal_correspondence_evidence_for(command_line.clone(), profile, params, &entropy);
        assert_eq!(
            evidence.representation_version,
            LATTICE_REPRESENTATION_VERSION
        );
        assert_eq!(
            evidence.public_matrix_material_version,
            PUBLIC_MATRIX_MATERIAL_VERSION
        );
        assert_eq!(evidence.primitive_route_revision, PRIMITIVE_ROUTE_REVISION);
        assert!(
            evidence.checks.public_material_reconstruction
                && evidence.checks.route_profile_domain_separation
                && evidence.checks.operation_principal_domain_separation
                && evidence.checks.malformed_public_header_rejected
                && evidence.checks.malformed_tail_coefficients_rejected
                && evidence.checks.stale_route_revision_rejected
                && evidence.checks.unsupported_profile_rejected,
            "all formal correspondence checks must pass"
        );
        lines.push(serde_json::to_string(&evidence).expect("formal evidence serializes"));
    }

    for line in &lines {
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "formal correspondence evidence must not expose local paths: {line}"
        );
        assert!(
            !line.contains("trapdoor_coefficients")
                && !line.contains("secret_seed")
                && !line.contains("expanded_secret_matrix")
                && !line.contains("preimage_coefficients")
                && !line.contains("preimage_bytes")
                && !line.contains("bytes\":\""),
            "formal correspondence evidence must not expose secret material: {line}"
        );
        assert!(
            !line.contains("op:")
                && !line.contains("principal:")
                && !line.contains("formal-read")
                && !line.contains("formal-principal"),
            "formal correspondence evidence must hash or omit request text: {line}"
        );
        eprintln!("{line}");
    }
    write_formal_correspondence_jsonl_artifact(&lines);
    assert!(
        fs::metadata(FORMAL_CORRESPONDENCE_ARTIFACT_PATH)
            .expect("formal correspondence evidence artifact exists")
            .len()
            > 0,
        "formal correspondence evidence artifact must be non-empty"
    );
}

#[test]
fn representation_profile_evidence_jsonl_is_secret_free() {
    let mut lines = Vec::new();
    for (name, params) in [
        ("SMALL_TEST", LatticeParams::SMALL_TEST),
        ("V4_REFERENCE", LatticeParams::V4_REFERENCE),
    ] {
        let evidence = evidence_for(name, params);
        assert_eq!(
            evidence.representation_version,
            LATTICE_REPRESENTATION_VERSION
        );
        assert!(
            evidence.redaction.master_trapdoor_debug_redacted,
            "master trapdoor debug must redact secret material"
        );
        assert!(
            evidence.redaction.zone_period_trapdoor_debug_redacted,
            "zone-period trapdoor debug must redact secret material"
        );
        assert!(
            evidence.redaction.preimage_debug_redacted,
            "preimage debug must redact signature material"
        );
        assert!(
            evidence
                .policy_bridge_compatibility
                .preimage_length_matches_profile,
            "policy bridge must consume the profile-derived preimage length"
        );
        assert_eq!(
            evidence.relation_check_result.root,
            TrapdoorRelationResult::MetadataConsistent,
            "root relation must validate against the route public key"
        );
        assert_eq!(
            evidence.relation_check_result.child,
            TrapdoorRelationResult::MetadataConsistent,
            "child relation must validate against the route public key"
        );
        assert_eq!(
            evidence.trapdoor_norm_quality_bucket.root,
            TrapdoorNormQualityBucket::Small,
            "route trapdoor should report a bounded basis norm bucket"
        );

        let line = serde_json::to_string(&evidence).expect("evidence log serializes");
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "evidence log must not expose local paths: {line}"
        );
        assert!(
            !line.contains("secret_material"),
            "evidence log must not include debug secret labels: {line}"
        );
        assert!(
            !line.contains("pool-material") && !line.contains("preimage_bytes"),
            "evidence log must not expose secret payload labels: {line}"
        );
        assert!(
            !line.contains("op:read") && !line.contains("principal:alice"),
            "evidence log must not expose raw operation or principal text: {line}"
        );
        eprintln!("{line}");
        lines.push(line);
    }
    write_jsonl_artifact(&lines);
    assert!(
        fs::metadata(ARTIFACT_PATH)
            .expect("evidence artifact exists")
            .len()
            > 0,
        "evidence artifact must be non-empty"
    );
}

fn public_material_summary(
    binding_hash: [u8; 32],
    kind: PublicMatrixMaterialKind,
    public_seed_bytes: usize,
    tail_coefficients_bytes: usize,
    material_digest: Option<[u8; 32]>,
) -> PublicMaterialSummary {
    PublicMaterialSummary {
        kind,
        public_seed_bytes,
        tail_coefficients_bytes,
        binding_hash_hex: hex::encode(binding_hash),
        material_digest_hex: material_digest.map(hex::encode),
    }
}

fn h_fixture_id(profile: &str, scenario: &str, h: OperationHash) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-pq/sample-pre-verify-h-fixture-v1|");
    hasher.update(profile.as_bytes());
    hasher.update(scenario.as_bytes());
    hasher.update(&h.0);
    format!("hash:{}", hex::encode(hasher.finalize().as_bytes()))
}

const fn observed_norm_bucket(norm_squared: u128, bound_squared: u128) -> &'static str {
    if norm_squared == 0 {
        "zero"
    } else if norm_squared > bound_squared {
        "over_bound"
    } else if norm_squared <= bound_squared / 4 {
        "lte_25_percent_bound"
    } else if norm_squared <= bound_squared / 2 {
        "lte_50_percent_bound"
    } else {
        "lte_bound"
    }
}

const fn verify_outcome_and_mapping(
    outcome: &Result<(), LatticePqError>,
) -> (&'static str, Option<&'static str>, &'static str) {
    match outcome {
        Ok(()) => ("passed", None, "passed"),
        Err(LatticePqError::VerificationEquationFailed) => {
            ("denied", Some("VerificationEquationFailed"), "denied")
        }
        Err(LatticePqError::PreimageNormTooLarge { .. }) => {
            ("denied", Some("PreimageNormTooLarge"), "denied")
        }
        Err(LatticePqError::ParameterMismatch { .. }) => {
            ("denied", Some("ParameterMismatch"), "denied")
        }
        Err(LatticePqError::OutsidePeriod { .. }) => ("denied", Some("OutsidePeriod"), "denied"),
        Err(LatticePqError::InvalidEncodingLength { .. }) => {
            ("denied", Some("InvalidEncodingLength"), "denied")
        }
        Err(LatticePqError::InvalidParameter { .. }) => {
            ("denied", Some("InvalidParameter"), "denied")
        }
        Err(LatticePqError::UnsupportedPrimitiveRoute { .. }) => {
            ("denied", Some("UnsupportedPrimitiveRoute"), "denied")
        }
        Err(LatticePqError::InvalidTrapdoorSecret { .. }) => {
            ("denied", Some("InvalidTrapdoorSecret"), "denied")
        }
        Err(LatticePqError::RepresentationTooLarge { .. }) => {
            ("denied", Some("RepresentationTooLarge"), "denied")
        }
        Err(LatticePqError::InvalidPeriod { .. }) => ("denied", Some("InvalidPeriod"), "denied"),
        Err(LatticePqError::NotImplemented { .. }) => ("failed", Some("NotImplemented"), "failed"),
    }
}

fn constant_preimage(params: LatticeParams, coeff: u64) -> LatticePreimage {
    let coefficient_bytes = params
        .coefficient_bytes()
        .expect("test params have coefficient width");
    let coeff_bytes = coeff.to_le_bytes();
    let mut bytes = Vec::with_capacity(
        params
            .preimage_encoded_bytes()
            .expect("test params have preimage length"),
    );
    for _ in 0..params.m {
        bytes.extend_from_slice(&coeff_bytes[..coefficient_bytes]);
    }
    LatticePreimage::from_encoded_bytes(params, bytes).expect("constant preimage length is valid")
}

#[allow(clippy::too_many_arguments)]
fn sample_pre_verify_evidence<'a>(
    command_line: Cow<'a, str>,
    profile: &'a str,
    params: LatticeParams,
    representation: &LatticeRepresentationProfile,
    zone: &[u8; 32],
    period: DelegationPeriod,
    scenario: &'a str,
    h: OperationHash,
    norm_bound_squared: u128,
    observed_norm_squared: u128,
    primitive_timings_ms: PrimitiveTimings,
    outcome: &Result<(), LatticePqError>,
    skip_reason: Option<&'a str>,
) -> SamplePreVerifyEvidenceLog<'a> {
    let (verify_outcome, error_mapping, result) = verify_outcome_and_mapping(outcome);
    SamplePreVerifyEvidenceLog {
        command_line,
        git_revision: git_revision(),
        primitive_route_id: PRIMITIVE_ROUTE_ID,
        primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        parameter_profile: profile,
        fixture_id: hashed_fixture_id(),
        zone_id_hash: zone_id_hash(zone),
        period_id_hash: period_id_hash(period),
        h_fixture_id: h_fixture_id(profile, scenario, h),
        matrix_dimensions: matrix_dimensions(params, representation),
        norm_bound_squared,
        observed_norm_squared,
        observed_norm_bucket: observed_norm_bucket(observed_norm_squared, norm_bound_squared),
        primitive_timings_ms,
        verify_outcome,
        error_mapping,
        timeout_cancel_result: "not_applicable_sync_arithmetic",
        cleanup: "artifact_rewritten",
        result,
        skip_reason,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Evidence scenarios are intentionally explicit.
fn public_matrix_reconstruction_evidence_jsonl_is_secret_free() {
    let command_line = evidence_command_line(
        "FCP_CRYPTO_PQ_PUBLIC_MATRIX_EVIDENCE_COMMAND_LINE",
        PUBLIC_MATRIX_EVIDENCE_COMMAND,
    );
    let started = Instant::now();
    let zone = [0xA5; 32];
    let period = period();
    let small = LatticeParams::SMALL_TEST;
    let small_representation = small
        .representation_profile()
        .expect("small profile representation is bounded");
    let entropy = route_fixture_entropy();
    let (master_pub, master_trap) =
        trap_gen_with_entropy(small, &entropy).expect("SMALL_TEST route TrapGen succeeds");
    let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, period, small)
        .expect("SMALL_TEST route Delegate succeeds");
    let material_digest = reconstruct_public_matrix_digest(&zone_pub, small)
        .expect("public matrix digest reconstructs");
    let abar_coeff = reconstruct_public_matrix_coefficient(&zone_pub, 0, 0, small)
        .expect("A_bar coefficient reconstructs");
    let tail_coeff = reconstruct_public_matrix_coefficient(&zone_pub, 0, small.m - small.n, small)
        .expect("tail coefficient reconstructs");
    assert!(abar_coeff < small.q);
    assert!(tail_coeff < small.q);
    let child_relation = zone_trap.relation_summary(&zone_pub, &master_pub);
    assert_eq!(
        child_relation.result,
        TrapdoorRelationResult::MetadataConsistent
    );

    let base_success = PublicMatrixEvidenceLog {
        command_line: command_line.clone(),
        git_revision: git_revision(),
        primitive_route_id: PRIMITIVE_ROUTE_ID,
        primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
        parameter_profile: primitive_route_profile_name(small),
        fixture_id: hashed_fixture_id(),
        zone_id_hash: zone_id_hash(&zone),
        period_id_hash: period_id_hash(period),
        public_material_summary: public_material_summary(
            zone_pub.hash,
            zone_pub.public_matrix.kind,
            zone_pub.public_matrix.seed().len(),
            zone_pub.public_matrix.tail_coefficients_len(),
            Some(material_digest),
        ),
        matrix_dimensions: matrix_dimensions(small, &small_representation),
        child_relation_result: Some(child_relation.result),
        reconstruction_result: "passed",
        allocation_summary: allocation_estimate(&small_representation),
        timing_ms: started.elapsed().as_millis(),
        result: "passed",
        skip_reason: None,
    };
    let mut malformed_tail = zone_pub.clone();
    malformed_tail.public_matrix.tail_coefficients.pop();
    let malformed_tail_result = reconstruct_public_matrix_digest(&malformed_tail, small);
    assert!(matches!(
        malformed_tail_result,
        Err(LatticePqError::InvalidEncodingLength {
            material: "public_matrix_tail",
            ..
        })
    ));

    let mut wrong_binding = zone_pub.clone();
    wrong_binding.hash[0] ^= 0x80;
    let wrong_binding_relation = zone_trap.relation_summary(&wrong_binding, &master_pub);
    assert_eq!(
        wrong_binding_relation.result,
        TrapdoorRelationResult::MetadataMismatch
    );

    let mut wrong_seed = zone_pub.clone();
    wrong_seed.public_matrix.public_seed[0] ^= 0x01;
    assert_ne!(
        reconstruct_public_matrix_digest(&wrong_seed, small).expect("wrong seed still encodes"),
        material_digest,
        "public seed must affect verifier reconstruction"
    );
    let wrong_seed_relation = zone_trap.relation_summary(&wrong_seed, &master_pub);
    assert_eq!(
        wrong_seed_relation.result,
        TrapdoorRelationResult::MetadataMismatch
    );

    let mut wrong_route = zone_pub;
    wrong_route.public_matrix.route_revision += 1;
    let wrong_route_result = reconstruct_public_matrix_digest(&wrong_route, small);
    assert!(matches!(
        wrong_route_result,
        Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_material",
            ..
        })
    ));

    let v4 = LatticeParams::V4_REFERENCE;
    let v4_representation = v4
        .representation_profile()
        .expect("V4 representation remains allocation bounded");
    let (v4_master_pub, v4_master_trap) =
        trap_gen_with_entropy(v4, &entropy).expect("V4 route TrapGen succeeds");
    let (v4_zone_pub, v4_zone_trap) = delegate(&v4_master_pub, &v4_master_trap, zone, period, v4)
        .expect("V4 route Delegate succeeds");
    let v4_material_digest =
        reconstruct_public_matrix_digest(&v4_zone_pub, v4).expect("V4 digest reconstructs");
    let v4_abar_coeff = reconstruct_public_matrix_coefficient(&v4_zone_pub, 0, 0, v4)
        .expect("V4 A_bar coefficient reconstructs");
    let v4_tail_coeff = reconstruct_public_matrix_coefficient(&v4_zone_pub, 0, v4.m - v4.n, v4)
        .expect("V4 tail coefficient reconstructs");
    assert!(v4_abar_coeff < v4.q);
    assert!(v4_tail_coeff < v4.q);
    let v4_child_relation = v4_zone_trap.relation_summary(&v4_zone_pub, &v4_master_pub);
    assert_eq!(
        v4_child_relation.result,
        TrapdoorRelationResult::MetadataConsistent
    );
    assert_eq!(
        v4_zone_pub.public_matrix.tail_coefficients_len(),
        usize::try_from(v4.n).expect("n fits")
            * usize::try_from(v4.n).expect("n fits")
            * v4.coefficient_bytes().expect("V4 coefficient bytes")
    );

    let v4_success = PublicMatrixEvidenceLog {
        command_line: command_line.clone(),
        git_revision: git_revision(),
        primitive_route_id: PRIMITIVE_ROUTE_ID,
        primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
        parameter_profile: primitive_route_profile_name(v4),
        fixture_id: hashed_fixture_id(),
        zone_id_hash: zone_id_hash(&zone),
        period_id_hash: period_id_hash(period),
        public_material_summary: public_material_summary(
            v4_zone_pub.hash,
            v4_zone_pub.public_matrix.kind,
            v4_zone_pub.public_matrix.seed().len(),
            v4_zone_pub.public_matrix.tail_coefficients_len(),
            Some(v4_material_digest),
        ),
        matrix_dimensions: matrix_dimensions(v4, &v4_representation),
        child_relation_result: Some(v4_child_relation.result),
        reconstruction_result: "passed",
        allocation_summary: allocation_estimate(&v4_representation),
        timing_ms: started.elapsed().as_millis(),
        result: "passed",
        skip_reason: None,
    };

    let mut v4_malformed_tail = v4_zone_pub.clone();
    v4_malformed_tail.public_matrix.tail_coefficients.pop();
    let v4_malformed_tail_result = reconstruct_public_matrix_digest(&v4_malformed_tail, v4);
    assert!(matches!(
        v4_malformed_tail_result,
        Err(LatticePqError::InvalidEncodingLength {
            material: "public_matrix_tail",
            ..
        })
    ));

    let mut v4_wrong_binding = v4_zone_pub.clone();
    v4_wrong_binding.hash[0] ^= 0x80;
    let v4_wrong_binding_relation =
        v4_zone_trap.relation_summary(&v4_wrong_binding, &v4_master_pub);
    assert_eq!(
        v4_wrong_binding_relation.result,
        TrapdoorRelationResult::MetadataMismatch
    );

    let mut v4_wrong_seed = v4_zone_pub.clone();
    v4_wrong_seed.public_matrix.public_seed[0] ^= 0x01;
    assert_ne!(
        reconstruct_public_matrix_digest(&v4_wrong_seed, v4).expect("wrong V4 seed encodes"),
        v4_material_digest,
        "V4 public seed must affect verifier reconstruction"
    );
    let v4_wrong_seed_relation = v4_zone_trap.relation_summary(&v4_wrong_seed, &v4_master_pub);
    assert_eq!(
        v4_wrong_seed_relation.result,
        TrapdoorRelationResult::MetadataMismatch
    );

    let mut v4_wrong_route = v4_zone_pub;
    v4_wrong_route.public_matrix.route_revision += 1;
    let v4_wrong_route_result = reconstruct_public_matrix_digest(&v4_wrong_route, v4);
    assert!(matches!(
        v4_wrong_route_result,
        Err(LatticePqError::InvalidTrapdoorSecret {
            material: "public_matrix_material",
            ..
        })
    ));

    let mut custom = LatticeParams::V4_REFERENCE;
    custom.depth = 3;
    let custom_representation = custom
        .representation_profile()
        .expect("custom representation remains allocation bounded");
    let (fixture_master_pub, fixture_master_trap) =
        trap_gen_fixture(custom).expect("fixture custom setup succeeds");
    let (fixture_zone_pub, _) = delegate_fixture(
        &fixture_master_pub,
        &fixture_master_trap,
        zone,
        period,
        custom,
    )
    .expect("fixture custom delegate succeeds");
    let unsupported_custom = reconstruct_public_matrix_coefficient(&fixture_zone_pub, 0, 0, custom);
    assert!(matches!(
        unsupported_custom,
        Err(LatticePqError::UnsupportedPrimitiveRoute { .. })
    ));

    let mut lines = vec![
        serde_json::to_string(&base_success).expect("evidence serializes"),
        serde_json::to_string(&v4_success).expect("V4 evidence serializes"),
    ];

    for evidence in [
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(small),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                malformed_tail.hash,
                malformed_tail.public_matrix.kind,
                malformed_tail.public_matrix.seed().len(),
                malformed_tail.public_matrix.tail_coefficients_len(),
                None,
            ),
            matrix_dimensions: matrix_dimensions(small, &small_representation),
            child_relation_result: None,
            reconstruction_result: "invalid_encoding_length",
            allocation_summary: allocation_estimate(&small_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("malformed public tail"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(small),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                wrong_binding.hash,
                wrong_binding.public_matrix.kind,
                wrong_binding.public_matrix.seed().len(),
                wrong_binding.public_matrix.tail_coefficients_len(),
                Some(reconstruct_public_matrix_digest(&wrong_binding, small).unwrap()),
            ),
            matrix_dimensions: matrix_dimensions(small, &small_representation),
            child_relation_result: Some(wrong_binding_relation.result),
            reconstruction_result: "binding_mismatch",
            allocation_summary: allocation_estimate(&small_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("wrong public binding hash"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(small),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                wrong_seed.hash,
                wrong_seed.public_matrix.kind,
                wrong_seed.public_matrix.seed().len(),
                wrong_seed.public_matrix.tail_coefficients_len(),
                Some(reconstruct_public_matrix_digest(&wrong_seed, small).unwrap()),
            ),
            matrix_dimensions: matrix_dimensions(small, &small_representation),
            child_relation_result: Some(wrong_seed_relation.result),
            reconstruction_result: "public_seed_mismatch",
            allocation_summary: allocation_estimate(&small_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("wrong public seed"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(small),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                wrong_route.hash,
                wrong_route.public_matrix.kind,
                wrong_route.public_matrix.seed().len(),
                wrong_route.public_matrix.tail_coefficients_len(),
                None,
            ),
            matrix_dimensions: matrix_dimensions(small, &small_representation),
            child_relation_result: None,
            reconstruction_result: "route_mismatch",
            allocation_summary: allocation_estimate(&small_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("wrong route revision"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(v4),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                v4_malformed_tail.hash,
                v4_malformed_tail.public_matrix.kind,
                v4_malformed_tail.public_matrix.seed().len(),
                v4_malformed_tail.public_matrix.tail_coefficients_len(),
                None,
            ),
            matrix_dimensions: matrix_dimensions(v4, &v4_representation),
            child_relation_result: None,
            reconstruction_result: "invalid_encoding_length",
            allocation_summary: allocation_estimate(&v4_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("V4 malformed public tail"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(v4),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                v4_wrong_binding.hash,
                v4_wrong_binding.public_matrix.kind,
                v4_wrong_binding.public_matrix.seed().len(),
                v4_wrong_binding.public_matrix.tail_coefficients_len(),
                Some(reconstruct_public_matrix_digest(&v4_wrong_binding, v4).unwrap()),
            ),
            matrix_dimensions: matrix_dimensions(v4, &v4_representation),
            child_relation_result: Some(v4_wrong_binding_relation.result),
            reconstruction_result: "binding_mismatch",
            allocation_summary: allocation_estimate(&v4_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("V4 wrong public binding hash"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(v4),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                v4_wrong_seed.hash,
                v4_wrong_seed.public_matrix.kind,
                v4_wrong_seed.public_matrix.seed().len(),
                v4_wrong_seed.public_matrix.tail_coefficients_len(),
                Some(reconstruct_public_matrix_digest(&v4_wrong_seed, v4).unwrap()),
            ),
            matrix_dimensions: matrix_dimensions(v4, &v4_representation),
            child_relation_result: Some(v4_wrong_seed_relation.result),
            reconstruction_result: "public_seed_mismatch",
            allocation_summary: allocation_estimate(&v4_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("V4 wrong public seed"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(v4),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                v4_wrong_route.hash,
                v4_wrong_route.public_matrix.kind,
                v4_wrong_route.public_matrix.seed().len(),
                v4_wrong_route.public_matrix.tail_coefficients_len(),
                None,
            ),
            matrix_dimensions: matrix_dimensions(v4, &v4_representation),
            child_relation_result: None,
            reconstruction_result: "route_mismatch",
            allocation_summary: allocation_estimate(&v4_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("V4 wrong route revision"),
        },
        PublicMatrixEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            public_matrix_material_version: PUBLIC_MATRIX_MATERIAL_VERSION,
            parameter_profile: primitive_route_profile_name(custom),
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            public_material_summary: public_material_summary(
                fixture_zone_pub.hash,
                fixture_zone_pub.public_matrix.kind,
                fixture_zone_pub.public_matrix.seed().len(),
                fixture_zone_pub.public_matrix.tail_coefficients_len(),
                None,
            ),
            matrix_dimensions: matrix_dimensions(custom, &custom_representation),
            child_relation_result: None,
            reconstruction_result: "unsupported_profile",
            allocation_summary: allocation_estimate(&custom_representation),
            timing_ms: started.elapsed().as_millis(),
            result: "denied",
            skip_reason: Some("unsupported custom profile"),
        },
    ] {
        lines.push(serde_json::to_string(&evidence).expect("denial evidence serializes"));
    }

    for line in &lines {
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "public matrix evidence must not expose local paths: {line}"
        );
        assert!(
            !line.contains("trapdoor_coefficients")
                && !line.contains("secret_seed")
                && !line.contains("expanded_secret_matrix")
                && !line.contains("preimage_coefficients"),
            "public matrix evidence must not expose forbidden secret labels: {line}"
        );
        assert!(
            !line.contains("op:") && !line.contains("principal:") && !line.contains("alice"),
            "public matrix evidence must not expose raw operation/principal text or PII: {line}"
        );
        assert!(
            !line.contains("tail_coefficients\":\""),
            "public matrix evidence must summarize public material instead of dumping it: {line}"
        );
        eprintln!("{line}");
    }
    write_public_matrix_jsonl_artifact(&lines);
    assert!(
        fs::metadata(PUBLIC_MATRIX_ARTIFACT_PATH)
            .expect("public matrix evidence artifact exists")
            .len()
            > 0,
        "public matrix evidence artifact must be non-empty"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep SamplePre/Verify evidence cases explicit.
fn sample_pre_verify_evidence_jsonl_is_secret_free() {
    let command_line = evidence_command_line(
        "FCP_CRYPTO_PQ_SAMPLE_PRE_VERIFY_EVIDENCE_COMMAND_LINE",
        SAMPLE_PRE_VERIFY_EVIDENCE_COMMAND,
    );
    let zone = [0xA5; 32];
    let period = period();
    let mut lines = Vec::new();

    for (profile, params) in [
        ("SMALL_TEST", LatticeParams::SMALL_TEST),
        ("V4_REFERENCE", LatticeParams::V4_REFERENCE),
    ] {
        let representation = params
            .representation_profile()
            .expect("profile representation is bounded");
        let entropy = route_fixture_entropy();
        let trap_gen_started = Instant::now();
        let (master_pub, master_trap) =
            trap_gen_with_entropy(params, &entropy).expect("route TrapGen succeeds");
        let trap_gen_ms = trap_gen_started.elapsed().as_millis();

        let delegate_started = Instant::now();
        let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, period, params)
            .expect("route Delegate succeeds");
        let delegate_ms = delegate_started.elapsed().as_millis();

        let h = operation_hash(
            &zone,
            period,
            b"sample-pre-verify:read",
            b"sample-principal",
        );
        let rhs = expand_operation_hash_rhs(h, params);
        assert_eq!(
            rhs.len(),
            usize::try_from(params.n).expect("u32 n fits in usize")
        );

        let sample_started = Instant::now();
        let preimage =
            sample_pre(&zone_pub, &zone_trap, h, params).expect("route SamplePre succeeds");
        let sample_pre_ms = sample_started.elapsed().as_millis();
        let norm_bound_squared = preimage_norm_bound_squared(params).expect("norm bound computes");
        let observed_norm_squared =
            preimage_norm_squared(params, &preimage).expect("sample norm computes");
        assert!(
            observed_norm_squared <= norm_bound_squared,
            "sampled norm must fit bound"
        );

        let verify_started = Instant::now();
        let success = verify(&zone_pub, h, &preimage, period.start_secs, params);
        let verify_ms = verify_started.elapsed().as_millis();
        assert!(success.is_ok(), "success case must verify: {success:?}");
        let timings = PrimitiveTimings {
            trap_gen: trap_gen_ms,
            delegate: delegate_ms,
            sample_pre: sample_pre_ms,
            verify: verify_ms,
        };
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "success",
            h,
            norm_bound_squared,
            observed_norm_squared,
            timings,
            &success,
            None,
        );
        lines.push(serde_json::to_string(&evidence).expect("success evidence serializes"));

        let forged_equation = LatticePreimage::fixture_zero(params).expect("zero preimage exists");
        let verify_started = Instant::now();
        let forged_equation_result =
            verify(&zone_pub, h, &forged_equation, period.start_secs, params);
        let forged_verify_ms = verify_started.elapsed().as_millis();
        assert!(
            matches!(
                forged_equation_result,
                Err(LatticePqError::VerificationEquationFailed)
            ),
            "forged equation must fail with equation mapping: {forged_equation_result:?}"
        );
        let forged_norm =
            preimage_norm_squared(params, &forged_equation).expect("forged norm computes");
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "forged equation",
            h,
            norm_bound_squared,
            forged_norm,
            PrimitiveTimings {
                verify: forged_verify_ms,
                ..timings
            },
            &forged_equation_result,
            Some("forged equation"),
        );
        lines.push(serde_json::to_string(&evidence).expect("forged evidence serializes"));

        let too_large = constant_preimage(params, params.q / 2);
        let verify_started = Instant::now();
        let over_norm_result = verify(&zone_pub, h, &too_large, period.start_secs, params);
        let over_norm_verify_ms = verify_started.elapsed().as_millis();
        assert!(
            matches!(
                over_norm_result,
                Err(LatticePqError::PreimageNormTooLarge { .. })
            ),
            "over-norm preimage must map to norm error: {over_norm_result:?}"
        );
        let over_norm = preimage_norm_squared(params, &too_large).expect("over norm computes");
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "wrong norm",
            h,
            norm_bound_squared,
            over_norm,
            PrimitiveTimings {
                verify: over_norm_verify_ms,
                ..timings
            },
            &over_norm_result,
            Some("wrong norm"),
        );
        lines.push(serde_json::to_string(&evidence).expect("norm evidence serializes"));

        let wrong_zone_h = operation_hash(
            &[0xA6; 32],
            period,
            b"sample-pre-verify:read",
            b"sample-principal",
        );
        let verify_started = Instant::now();
        let wrong_zone_result = verify(
            &zone_pub,
            wrong_zone_h,
            &preimage,
            period.start_secs,
            params,
        );
        let wrong_zone_verify_ms = verify_started.elapsed().as_millis();
        assert!(
            matches!(
                wrong_zone_result,
                Err(LatticePqError::VerificationEquationFailed)
            ),
            "wrong zone RHS must fail equation: {wrong_zone_result:?}"
        );
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "wrong zone",
            wrong_zone_h,
            norm_bound_squared,
            observed_norm_squared,
            PrimitiveTimings {
                verify: wrong_zone_verify_ms,
                ..timings
            },
            &wrong_zone_result,
            Some("wrong zone"),
        );
        lines.push(serde_json::to_string(&evidence).expect("wrong-zone evidence serializes"));

        let wrong_period = DelegationPeriod {
            start_secs: period.start_secs + 60,
            end_secs: period.end_secs + 60,
        };
        let wrong_period_h = operation_hash(
            &zone,
            wrong_period,
            b"sample-pre-verify:read",
            b"sample-principal",
        );
        let verify_started = Instant::now();
        let wrong_period_result = verify(
            &zone_pub,
            wrong_period_h,
            &preimage,
            period.start_secs,
            params,
        );
        let wrong_period_verify_ms = verify_started.elapsed().as_millis();
        assert!(
            matches!(
                wrong_period_result,
                Err(LatticePqError::VerificationEquationFailed)
            ),
            "wrong period RHS must fail equation: {wrong_period_result:?}"
        );
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "wrong period",
            wrong_period_h,
            norm_bound_squared,
            observed_norm_squared,
            PrimitiveTimings {
                verify: wrong_period_verify_ms,
                ..timings
            },
            &wrong_period_result,
            Some("wrong period"),
        );
        lines.push(serde_json::to_string(&evidence).expect("wrong-period evidence serializes"));

        let mut malformed = preimage.clone();
        malformed.bytes.pop();
        let verify_started = Instant::now();
        let malformed_result = verify(&zone_pub, h, &malformed, period.start_secs, params);
        let malformed_verify_ms = verify_started.elapsed().as_millis();
        assert!(
            matches!(
                malformed_result,
                Err(LatticePqError::InvalidEncodingLength {
                    material: "preimage",
                    ..
                })
            ),
            "malformed preimage must fail length mapping: {malformed_result:?}"
        );
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "malformed preimage",
            h,
            norm_bound_squared,
            0,
            PrimitiveTimings {
                verify: malformed_verify_ms,
                ..timings
            },
            &malformed_result,
            Some("malformed preimage"),
        );
        lines.push(serde_json::to_string(&evidence).expect("malformed evidence serializes"));

        let verify_started = Instant::now();
        let outside_period_result = verify(&zone_pub, h, &preimage, period.end_secs, params);
        let outside_period_verify_ms = verify_started.elapsed().as_millis();
        assert!(
            matches!(
                outside_period_result,
                Err(LatticePqError::OutsidePeriod { .. })
            ),
            "outside period must fail before arithmetic: {outside_period_result:?}"
        );
        let evidence = sample_pre_verify_evidence(
            command_line.clone(),
            profile,
            params,
            &representation,
            &zone,
            period,
            "outside period",
            h,
            norm_bound_squared,
            observed_norm_squared,
            PrimitiveTimings {
                verify: outside_period_verify_ms,
                ..timings
            },
            &outside_period_result,
            Some("outside period"),
        );
        lines.push(serde_json::to_string(&evidence).expect("outside-period evidence serializes"));
    }

    for line in &lines {
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "SamplePre/Verify evidence must not expose local paths: {line}"
        );
        assert!(
            !line.contains("trapdoor_coefficients")
                && !line.contains("secret_seed")
                && !line.contains("expanded_secret_matrix")
                && !line.contains("preimage_coefficients")
                && !line.contains("preimage_bytes")
                && !line.contains("bytes\":\""),
            "SamplePre/Verify evidence must not expose preimage/trapdoor material: {line}"
        );
        assert!(
            !line.contains("op:") && !line.contains("principal:") && !line.contains("alice"),
            "SamplePre/Verify evidence must not expose raw operation/principal text or PII: {line}"
        );
        eprintln!("{line}");
    }
    write_sample_pre_verify_jsonl_artifact(&lines);
    assert!(
        fs::metadata(SAMPLE_PRE_VERIFY_ARTIFACT_PATH)
            .expect("SamplePre/Verify evidence artifact exists")
            .len()
            > 0,
        "SamplePre/Verify evidence artifact must be non-empty"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the e2e evidence scenarios linear and auditable.
fn trapgen_delegate_route_evidence_jsonl_is_secret_free() {
    let command_line = evidence_command_line(
        "FCP_CRYPTO_PQ_ROUTE_EVIDENCE_COMMAND_LINE",
        ROUTE_EVIDENCE_COMMAND,
    );
    let zone = [0xA5; 32];
    let period = period();
    let small = LatticeParams::SMALL_TEST;
    let v4 = LatticeParams::V4_REFERENCE;
    let mut unsupported_params = LatticeParams::V4_REFERENCE;
    unsupported_params.depth = 3;
    let small_representation = small
        .representation_profile()
        .expect("small profile representation is bounded");
    let v4_representation = v4
        .representation_profile()
        .expect("V4 profile representation is bounded");
    let unsupported_representation = unsupported_params
        .representation_profile()
        .expect("unsupported representation remains allocation bounded");
    let entropy = route_fixture_entropy();
    let small_started = Instant::now();
    let small_trap_gen_started = Instant::now();
    let (master_pub, master_trap) =
        trap_gen_with_entropy(small, &entropy).expect("SMALL_TEST route TrapGen succeeds");
    let small_trap_gen_ms = small_trap_gen_started.elapsed().as_millis();
    let small_delegate_started = Instant::now();
    let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, period, small)
        .expect("SMALL_TEST route Delegate succeeds");
    let small_delegate_ms = small_delegate_started.elapsed().as_millis();
    let small_relation_started = Instant::now();
    let root_relation = master_trap.relation_summary(&master_pub);
    let child_relation = zone_trap.relation_summary(&zone_pub, &master_pub);
    let small_relation_ms = small_relation_started.elapsed().as_millis();
    let small_timings = RoutePrimitiveTimings {
        trap_gen: small_trap_gen_ms,
        delegate: small_delegate_ms,
        relation_checks: small_relation_ms,
    };
    let base_success = RouteEvidenceLog {
        command_line: command_line.clone(),
        git_revision: git_revision(),
        primitive_route_id: PRIMITIVE_ROUTE_ID,
        primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        parameter_profile: primitive_route_profile_name(small),
        fixture_id: hashed_fixture_id(),
        zone_id_hash: zone_id_hash(&zone),
        period_id_hash: period_id_hash(period),
        matrix_dimensions: matrix_dimensions(small, &small_representation),
        root_relation_result: Some(root_relation.result),
        child_relation_result: Some(child_relation.result),
        trapdoor_norm_quality_bucket: RouteTrapdoorNormQualityEvidence {
            root: Some(root_relation.norm_quality_bucket),
            child: Some(child_relation.norm_quality_bucket),
        },
        allocation_summary: AllocationEstimate {
            public_matrix_expanded: small_representation.public_matrix_expanded_bytes,
            max_public_matrix_expanded: 64 * 1024 * 1024,
            preimage_encoded: small_representation.preimage_encoded_bytes,
            max_preimage_encoded: 1024 * 1024,
        },
        primitive_timings_ms: small_timings,
        timing_ms: small_started.elapsed().as_millis(),
        cleanup: "not_applicable_no_external_resources",
        result: "passed",
        skip_reason: None,
    };
    assert_eq!(
        base_success.root_relation_result,
        Some(TrapdoorRelationResult::MetadataConsistent)
    );
    assert_eq!(
        base_success.child_relation_result,
        Some(TrapdoorRelationResult::MetadataConsistent)
    );

    let mut lines = vec![serde_json::to_string(&base_success).expect("route evidence serializes")];

    let v4_entropy = v4_route_fixture_entropy();
    let v4_started = Instant::now();
    let v4_trap_gen_started = Instant::now();
    let (v4_master_pub, v4_master_trap) =
        trap_gen_with_entropy(v4, &v4_entropy).expect("V4 route TrapGen succeeds");
    let v4_trap_gen_ms = v4_trap_gen_started.elapsed().as_millis();
    let v4_delegate_started = Instant::now();
    let (v4_zone_pub, v4_zone_trap) = delegate(&v4_master_pub, &v4_master_trap, zone, period, v4)
        .expect("V4 route Delegate succeeds");
    let v4_delegate_ms = v4_delegate_started.elapsed().as_millis();
    let v4_relation_started = Instant::now();
    let v4_root_relation = v4_master_trap.relation_summary(&v4_master_pub);
    let v4_child_relation = v4_zone_trap.relation_summary(&v4_zone_pub, &v4_master_pub);
    let v4_relation_ms = v4_relation_started.elapsed().as_millis();
    let v4_timings = RoutePrimitiveTimings {
        trap_gen: v4_trap_gen_ms,
        delegate: v4_delegate_ms,
        relation_checks: v4_relation_ms,
    };
    let v4_success = RouteEvidenceLog {
        command_line: command_line.clone(),
        git_revision: git_revision(),
        primitive_route_id: PRIMITIVE_ROUTE_ID,
        primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
        representation_version: LATTICE_REPRESENTATION_VERSION,
        parameter_profile: primitive_route_profile_name(v4),
        fixture_id: hashed_fixture_id_for(V4_ROUTE_FIXTURE_ID),
        zone_id_hash: zone_id_hash(&zone),
        period_id_hash: period_id_hash(period),
        matrix_dimensions: matrix_dimensions(v4, &v4_representation),
        root_relation_result: Some(v4_root_relation.result),
        child_relation_result: Some(v4_child_relation.result),
        trapdoor_norm_quality_bucket: RouteTrapdoorNormQualityEvidence {
            root: Some(v4_root_relation.norm_quality_bucket),
            child: Some(v4_child_relation.norm_quality_bucket),
        },
        allocation_summary: allocation_estimate(&v4_representation),
        primitive_timings_ms: v4_timings,
        timing_ms: v4_started.elapsed().as_millis(),
        cleanup: "not_applicable_no_external_resources",
        result: "passed",
        skip_reason: None,
    };
    assert_eq!(
        v4_success.root_relation_result,
        Some(TrapdoorRelationResult::MetadataConsistent)
    );
    assert_eq!(
        v4_success.child_relation_result,
        Some(TrapdoorRelationResult::MetadataConsistent)
    );
    lines.push(serde_json::to_string(&v4_success).expect("V4 route evidence serializes"));

    let malformed_root =
        fcp_crypto_pq::MasterTrapdoor::from_basis_envelope(small, master_pub.hash, vec![0xAA; 32])
            .expect("malformed root envelope has valid length");
    let malformed_child = fcp_crypto_pq::ZonePeriodTrapdoor::from_basis_envelope(
        small,
        master_pub.hash,
        zone_pub.hash,
        vec![0x55; 32],
    )
    .expect("malformed child envelope has valid length");
    let denial_scenarios: Vec<(
        &str,
        Option<TrapdoorRelationResult>,
        Option<TrapdoorRelationResult>,
    )> = vec![
        (
            "malformed root basis",
            Some(malformed_root.relation_summary(&master_pub).result),
            None,
        ),
        (
            "malformed child basis",
            None,
            Some(
                malformed_child
                    .relation_summary(&zone_pub, &master_pub)
                    .result,
            ),
        ),
        ("wrong parent", None, {
            let other_entropy =
                TrapGenEntropy::from_fixture_seed(b"fixture:route-wrong-parent", [0xB6; 32]);
            let (other_parent_pub, _) = trap_gen_with_entropy(small, &other_entropy)
                .expect("alternate parent route setup succeeds");
            Some(
                zone_trap
                    .relation_summary(&zone_pub, &other_parent_pub)
                    .result,
            )
        }),
        ("wrong zone", None, {
            let mut wrong_zone_pub = zone_pub.clone();
            wrong_zone_pub.zone_id[0] ^= 0xFF;
            Some(
                zone_trap
                    .relation_summary(&wrong_zone_pub, &master_pub)
                    .result,
            )
        }),
        ("wrong period", None, {
            let mut wrong_period_pub = zone_pub.clone();
            wrong_period_pub.period.end_secs += 1;
            Some(
                zone_trap
                    .relation_summary(&wrong_period_pub, &master_pub)
                    .result,
            )
        }),
        ("wrong parameter profile", None, {
            let mut wrong_params_pub = zone_pub.clone();
            wrong_params_pub.params.q = 263;
            Some(
                zone_trap
                    .relation_summary(&wrong_params_pub, &master_pub)
                    .result,
            )
        }),
        ("unsupported custom profile", None, None),
        ("fixture-only trapdoor used on production route", None, None),
    ];

    for (scenario, root_result, child_result) in denial_scenarios {
        match scenario {
            "unsupported custom profile" => {
                let err = trap_gen_with_entropy(unsupported_params, &route_fixture_entropy())
                    .expect_err("unsupported custom route must fail closed");
                assert!(matches!(
                    err,
                    LatticePqError::UnsupportedPrimitiveRoute { .. }
                ));
            }
            "fixture-only trapdoor used on production route" => {
                let (fixture_pub, fixture_trap) =
                    trap_gen_fixture(small).expect("fixture setup succeeds");
                let err = delegate(&fixture_pub, &fixture_trap, zone, period, small)
                    .expect_err("fixture parent must not enter production delegate");
                assert!(matches!(
                    err,
                    LatticePqError::InvalidTrapdoorSecret {
                        material: "fixture_parent_trapdoor",
                        ..
                    }
                ));
            }
            _ => {
                if let Some(result) = root_result {
                    assert_eq!(result, TrapdoorRelationResult::MetadataMismatch);
                }
                if let Some(result) = child_result {
                    assert_eq!(result, TrapdoorRelationResult::MetadataMismatch);
                }
            }
        }

        let evidence = RouteEvidenceLog {
            command_line: command_line.clone(),
            git_revision: git_revision(),
            primitive_route_id: PRIMITIVE_ROUTE_ID,
            primitive_route_revision: PRIMITIVE_ROUTE_REVISION,
            representation_version: LATTICE_REPRESENTATION_VERSION,
            parameter_profile: if scenario == "unsupported custom profile" {
                primitive_route_profile_name(unsupported_params)
            } else {
                primitive_route_profile_name(small)
            },
            fixture_id: hashed_fixture_id(),
            zone_id_hash: zone_id_hash(&zone),
            period_id_hash: period_id_hash(period),
            matrix_dimensions: matrix_dimensions(
                if scenario == "unsupported custom profile" {
                    unsupported_params
                } else {
                    small
                },
                &if scenario == "unsupported custom profile" {
                    unsupported_representation
                } else {
                    small_representation
                },
            ),
            root_relation_result: root_result,
            child_relation_result: child_result,
            trapdoor_norm_quality_bucket: RouteTrapdoorNormQualityEvidence {
                root: root_result.map(|_| root_relation.norm_quality_bucket),
                child: child_result.map(|_| child_relation.norm_quality_bucket),
            },
            allocation_summary: allocation_estimate(&if scenario == "unsupported custom profile" {
                unsupported_representation
            } else {
                small_representation
            }),
            primitive_timings_ms: small_timings,
            timing_ms: small_started.elapsed().as_millis(),
            cleanup: "not_applicable_no_external_resources",
            result: "denied",
            skip_reason: Some(scenario),
        };
        let line = serde_json::to_string(&evidence).expect("denial evidence serializes");
        lines.push(line);
    }

    for line in &lines {
        assert!(
            !line.contains("/Users/") && !line.contains("/tmp/"),
            "route evidence must not expose local paths: {line}"
        );
        assert!(
            !line.contains("trapdoor_coefficients")
                && !line.contains("secret_seed")
                && !line.contains("expanded_secret_matrix"),
            "route evidence must not expose forbidden secret labels: {line}"
        );
        assert!(
            !line.contains("op:") && !line.contains("principal:") && !line.contains("alice"),
            "route evidence must not expose raw operation/principal text or PII: {line}"
        );
        assert!(
            !line.contains("fixture:small_test")
                && !line.contains("fixture:v4_reference")
                && !line.contains("route-wrong-parent"),
            "route evidence must hash fixture ids instead of logging raw names: {line}"
        );
        eprintln!("{line}");
    }
    write_route_jsonl_artifact(&lines);
    assert!(
        fs::metadata(ROUTE_ARTIFACT_PATH)
            .expect("route evidence artifact exists")
            .len()
            > 0,
        "route evidence artifact must be non-empty"
    );
}
